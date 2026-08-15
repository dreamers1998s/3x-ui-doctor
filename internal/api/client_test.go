package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPinnedTLSAndAuthorization(t *testing.T) {
	var authorization string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"obj":{}}`))
	}))
	defer server.Close()
	pin := sha256.Sum256(server.Certificate().Raw)
	client, err := New(Options{BaseURL: server.URL, Token: "top-secret", Timeout: time.Second, TLSPinSHA256: hex.EncodeToString(pin[:])})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.GetPanel(context.Background(), "/panel/api/server/status")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || authorization != "Bearer top-secret" {
		t.Fatalf("status/auth mismatch: %d %q", resp.StatusCode, authorization)
	}
}

func TestWrongPinFailsClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	client, err := New(Options{BaseURL: server.URL, Token: "secret", Timeout: time.Second, TLSPinSHA256: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetPanel(context.Background(), "/panel/api/server/status"); err == nil {
		t.Fatal("wrong pin was accepted")
	}
}

func TestExternalHostMustBeAllowlistedAndGetsNoAuthorization(t *testing.T) {
	var authorization string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("vless://uuid@example.com:443"))
	}))
	defer server.Close()
	pin := sha256.Sum256(server.Certificate().Raw)
	host := strings.TrimPrefix(server.URL, "https://")
	client, err := New(Options{BaseURL: "https://panel.invalid", Token: "secret", Timeout: time.Second, TLSPinSHA256: hex.EncodeToString(pin[:]), AllowedRedirectHosts: []string{host}})
	if err != nil {
		t.Fatal(err)
	}
	client.externalHTTP.Transport = server.Client().Transport
	if _, err := client.GetExternal(context.Background(), server.URL+"/sub/id"); err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		t.Fatalf("authorization leaked to subscription host: %q", authorization)
	}
}

func TestExternalHostDoesNotInheritPanelPin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("subscription"))
	}))
	defer server.Close()
	pin := sha256.Sum256(server.Certificate().Raw)
	host := strings.TrimPrefix(server.URL, "https://")
	client, err := New(Options{BaseURL: "https://panel.invalid", Token: "secret", Timeout: time.Second, TLSPinSHA256: hex.EncodeToString(pin[:]), AllowedRedirectHosts: []string{host}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetExternal(context.Background(), server.URL); err == nil {
		t.Fatal("external subscription inherited the panel certificate pin")
	}
}

func TestSameOriginSubscriptionUsesPanelPinWithoutAuthorization(t *testing.T) {
	var authorization string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("subscription"))
	}))
	defer server.Close()
	pin := sha256.Sum256(server.Certificate().Raw)
	client, err := New(Options{BaseURL: server.URL, Token: "secret", Timeout: time.Second, TLSPinSHA256: hex.EncodeToString(pin[:])})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetExternal(context.Background(), server.URL+"/sub/id"); err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		t.Fatalf("authorization leaked to same-origin subscription: %q", authorization)
	}
}

func TestPanelEndpointAllowlist(t *testing.T) {
	client, err := New(Options{BaseURL: "https://panel.example", Token: "secret", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetPanel(context.Background(), "/login"); err == nil {
		t.Fatal("non-panel endpoint allowed")
	}
	if _, err := client.GetPanel(context.Background(), "/panel/api/../login"); err == nil {
		t.Fatal("path traversal allowed")
	}
}

func TestRedirectDropsAuthorizationAcrossOrigins(t *testing.T) {
	var authorization string
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"obj":{}}`))
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/result", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	sourcePin := sha256.Sum256(source.Certificate().Raw)
	destinationHost := strings.TrimPrefix(destination.URL, "https://")
	client, err := New(Options{BaseURL: source.URL, Token: "redirect-secret", Timeout: time.Second, TLSPinSHA256: hex.EncodeToString(sourcePin[:]), AllowedRedirectHosts: []string{destinationHost}})
	if err != nil {
		t.Fatal(err)
	}
	// Panel API traffic never follows a cross-origin redirect, even when that
	// destination is allowlisted for external subscription traffic.
	_, err = client.GetPanel(context.Background(), "/panel/api/server/status")
	if err == nil {
		t.Fatal("panel cross-origin redirect was accepted")
	}
	if authorization != "" {
		t.Fatalf("authorization leaked across origin: %q", authorization)
	}
}

func TestRequestTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	pin := sha256.Sum256(server.Certificate().Raw)
	client, err := New(Options{BaseURL: server.URL, Token: "secret", Timeout: 10 * time.Millisecond, TLSPinSHA256: hex.EncodeToString(pin[:])})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetPanel(context.Background(), "/panel/api/server/status"); err == nil {
		t.Fatal("timeout was not enforced")
	}
}
