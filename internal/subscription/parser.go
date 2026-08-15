package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/redact"
	"gopkg.in/yaml.v3"
)

func Parse(format string, body []byte, r *redact.Redactor) ([]string, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("empty subscription body")
	}
	var values []string
	switch strings.ToLower(format) {
	case "raw", "links", "share":
		links, err := decodeLinks(body)
		if err != nil {
			return nil, err
		}
		for _, link := range links {
			canonical, err := canonicalLink(link)
			if err != nil {
				return nil, err
			}
			values = append(values, r.Digest(canonical))
		}
	case "json":
		var value any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid JSON subscription")
		}
		canonical, _ := json.Marshal(value)
		values = append(values, r.Digest(string(canonical)))
	case "clash", "yaml":
		var value any
		if err := yaml.Unmarshal(body, &value); err != nil {
			return nil, fmt.Errorf("invalid Clash YAML")
		}
		normalized := normalizeYAML(value)
		canonical, err := json.Marshal(normalized)
		if err != nil {
			return nil, fmt.Errorf("invalid Clash YAML values")
		}
		values = append(values, r.Digest(string(canonical)))
	default:
		return nil, fmt.Errorf("unsupported subscription format")
	}
	sort.Strings(values)
	return deduplicate(values), nil
}

func ParseLinkArray(body []byte, r *redact.Redactor) ([]string, error) {
	var links []string
	if err := json.Unmarshal(body, &links); err != nil {
		return nil, errors.New("invalid link array")
	}
	joined := []byte(strings.Join(links, "\n"))
	return Parse("links", joined, r)
}

func decodeLinks(body []byte) ([]string, error) {
	text := strings.TrimSpace(string(body))
	if !strings.Contains(text, "://") {
		var decoded []byte
		var err error
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err = encoding.DecodeString(strings.Map(func(r rune) rune {
				if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
					return -1
				}
				return r
			}, text))
			if err == nil {
				text = string(decoded)
				break
			}
		}
		if err != nil {
			return nil, errors.New("subscription is neither links nor valid Base64")
		}
	}
	var links []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		if line != "" {
			links = append(links, line)
		}
	}
	if len(links) == 0 {
		return nil, errors.New("subscription contains no links")
	}
	return links, nil
}

func canonicalLink(link string) (string, error) {
	if strings.HasPrefix(strings.ToLower(link), "vmess://") {
		payload := strings.TrimPrefix(link, "vmess://")
		decoded, err := decodeAnyBase64(payload)
		if err != nil {
			return "", errors.New("invalid VMess Base64")
		}
		var value map[string]any
		if err := json.Unmarshal(decoded, &value); err != nil {
			return "", errors.New("invalid VMess JSON")
		}
		for _, key := range []string{"add", "port", "id"} {
			if strings.TrimSpace(fmt.Sprint(value[key])) == "" || value[key] == nil {
				return "", errors.New("VMess JSON is missing required fields")
			}
		}
		if !validPort(fmt.Sprint(value["port"])) {
			return "", errors.New("VMess JSON has invalid port")
		}
		delete(value, "ps")
		canonical, _ := json.Marshal(value)
		return "vmess:" + string(canonical), nil
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme == "" {
		return "", errors.New("invalid share URI")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "ss", "shadowsocks":
		return canonicalShadowsocks(link)
	case "vless", "trojan":
		if u.User == nil || u.User.Username() == "" || !validURLHostPort(u) {
			return "", errors.New("share URI is missing credentials or endpoint")
		}
	case "hysteria", "hysteria2", "hy2":
		if !validURLHostPort(u) {
			return "", errors.New("share URI is missing endpoint")
		}
	default:
		return "", errors.New("unsupported share URI scheme")
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	u.RawQuery = u.Query().Encode()
	return u.String(), nil
}

func canonicalShadowsocks(link string) (string, error) {
	raw := link[strings.Index(link, "://")+3:]
	if fragment := strings.IndexByte(raw, '#'); fragment >= 0 {
		raw = raw[:fragment]
	}
	if query := strings.IndexByte(raw, '?'); query >= 0 {
		raw = raw[:query]
	}
	var credential, endpoint string
	if at := strings.LastIndexByte(raw, '@'); at >= 0 {
		credential, endpoint = raw[:at], raw[at+1:]
		if decoded, err := decodeAnyBase64(credential); err == nil {
			credential = string(decoded)
		}
	} else {
		decoded, err := decodeAnyBase64(raw)
		if err != nil {
			return "", errors.New("invalid Shadowsocks payload")
		}
		decodedText := string(decoded)
		at := strings.LastIndexByte(decodedText, '@')
		if at < 0 {
			return "", errors.New("Shadowsocks payload is missing endpoint")
		}
		credential, endpoint = decodedText[:at], decodedText[at+1:]
	}
	if !strings.Contains(credential, ":") || !validEndpoint(endpoint) {
		return "", errors.New("invalid Shadowsocks credentials or endpoint")
	}
	return "ss://" + credential + "@" + strings.ToLower(endpoint), nil
}

func validURLHostPort(u *url.URL) bool {
	return u.Hostname() != "" && validPort(u.Port())
}

func validEndpoint(endpoint string) bool {
	host, port, err := net.SplitHostPort(endpoint)
	return err == nil && host != "" && validPort(port)
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}

func decodeAnyBase64(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func normalizeYAML(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			out[key] = normalizeYAML(child)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			out[fmt.Sprint(key)] = normalizeYAML(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = normalizeYAML(child)
		}
		return out
	default:
		return v
	}
}

func deduplicate(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
