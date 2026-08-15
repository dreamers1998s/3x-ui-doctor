package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 32 << 20

var panelReadPostAllowlist = map[string]struct{}{
	"/panel/api/setting/all": {},
}

type Response struct {
	StatusCode  int
	ContentType string
	Body        []byte
	BodyHash    string
	BodyLength  int
	Latency     time.Duration
}

type Client struct {
	baseURL      *url.URL
	token        string
	panelHTTP    *http.Client
	externalHTTP *http.Client
	allowedHosts map[string]bool
}

type Options struct {
	BaseURL              string
	Token                string
	Timeout              time.Duration
	TLSPinSHA256         string
	ProxyURL             *url.URL
	AllowedRedirectHosts []string
}

func New(opts Options) (*Client, error) {
	base, err := url.Parse(opts.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, errors.New("invalid HTTPS panel base URL")
	}
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.Proxy = nil
	if opts.ProxyURL != nil {
		baseTransport.Proxy = http.ProxyURL(opts.ProxyURL)
	}
	baseTransport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	panelTransport := baseTransport.Clone()
	if opts.TLSPinSHA256 != "" {
		pin, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(opts.TLSPinSHA256), "sha256:"))
		if err != nil || len(pin) != sha256.Size {
			return nil, errors.New("invalid TLS certificate pin")
		}
		// A certificate pin is an explicit trust root. InsecureSkipVerify disables
		// the CA lookup only; VerifyConnection still fails closed on any mismatch.
		panelTransport.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 -- guarded by exact leaf pin below
		panelTransport.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("peer provided no certificate")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			if equalBytes(sum[:], pin) {
				return nil
			}
			return errors.New("TLS certificate pin mismatch")
		}
	}

	allowed := map[string]bool{}
	for _, host := range opts.AllowedRedirectHosts {
		allowed[strings.ToLower(host)] = true
	}
	panelHTTP := &http.Client{Transport: panelTransport, Timeout: opts.Timeout}
	panelHTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("redirect limit exceeded")
		}
		if !sameOrigin(via[0].URL, req.URL) {
			return errors.New("panel API cross-origin redirect rejected")
		}
		return nil
	}
	externalHTTP := &http.Client{Transport: baseTransport, Timeout: opts.Timeout}
	externalHTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("redirect limit exceeded")
		}
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		if !sameOrigin(via[0].URL, req.URL) && !allowed[strings.ToLower(req.URL.Host)] && !allowed[strings.ToLower(req.URL.Hostname())] {
			return errors.New("cross-origin redirect rejected")
		}
		return nil
	}
	return &Client{baseURL: base, token: opts.Token, panelHTTP: panelHTTP, externalHTTP: externalHTTP, allowedHosts: allowed}, nil
}

func (c *Client) GetPanel(ctx context.Context, path string) (Response, error) {
	u, err := c.panelURL(path)
	if err != nil {
		return Response{}, err
	}
	return c.request(ctx, c.panelHTTP, u, true, http.MethodGet, nil)
}

// PostPanelRead calls an upstream endpoint whose HTTP method is POST but whose
// documented semantics are read-only. The exact-path allowlist prevents this
// helper from becoming a general mutation surface.
func (c *Client) PostPanelRead(ctx context.Context, path string) (Response, error) {
	if _, ok := panelReadPostAllowlist[path]; !ok {
		return Response{}, errors.New("endpoint is not on the read-only POST allowlist")
	}
	u, err := c.panelURL(path)
	if err != nil {
		return Response{}, err
	}
	return c.request(ctx, c.panelHTTP, u, true, http.MethodPost, strings.NewReader("{}"))
}

func (c *Client) GetExternal(ctx context.Context, rawURL string) (Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return Response{}, errors.New("external URL must be HTTPS and contain no userinfo")
	}
	if !sameOrigin(c.baseURL, u) && !c.allowedHosts[strings.ToLower(u.Host)] && !c.allowedHosts[strings.ToLower(u.Hostname())] {
		return Response{}, errors.New("external host is not allowlisted")
	}
	hc := c.externalHTTP
	if sameOrigin(c.baseURL, u) {
		hc = c.panelHTTP
	}
	return c.request(ctx, hc, u, false, http.MethodGet, nil)
}

func (c *Client) panelURL(path string) (*url.URL, error) {
	if !strings.HasPrefix(path, "/panel/api/") || strings.Contains(path, "..") {
		return nil, errors.New("endpoint is not on the read-only panel API allowlist")
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	u.RawQuery = ""
	u.Fragment = ""
	return &u, nil
}

func (c *Client) request(ctx context.Context, hc *http.Client, u *url.URL, authenticated bool, method string, requestBody io.Reader) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), requestBody)
	if err != nil {
		return Response{}, errors.New("build request failed")
	}
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, text/plain;q=0.9, */*;q=0.1")
	req.Header.Set("User-Agent", "3x-ui-doctor/0.1")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated && sameOrigin(c.baseURL, u) {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	started := time.Now()
	resp, err := hc.Do(req)
	latency := time.Since(started)
	if err != nil {
		return Response{Latency: latency}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return Response{StatusCode: resp.StatusCode, Latency: latency}, errors.New("read response failed")
	}
	if len(body) > maxResponseBytes {
		return Response{StatusCode: resp.StatusCode, Latency: latency}, errors.New("response exceeded size limit")
	}
	contentType := resp.Header.Get("Content-Type")
	if parsed, _, parseErr := mime.ParseMediaType(contentType); parseErr == nil {
		contentType = parsed
	}
	sum := sha256.Sum256(body)
	r := Response{StatusCode: resp.StatusCode, ContentType: strings.ToLower(contentType), Body: body, BodyHash: hex.EncodeToString(sum[:]), BodyLength: len(body), Latency: latency}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return r, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	return r, nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(canonicalAuthority(a), canonicalAuthority(b))
}

func canonicalAuthority(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else if strings.EqualFold(u.Scheme, "http") {
			port = "80"
		}
	}
	return u.Hostname() + ":" + port
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
