package adapter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/redact"
)

func TestValidateOpenAPI(t *testing.T) {
	paths := map[string]any{}
	for path, methods := range RequiredOpenAPIPaths {
		ops := map[string]any{}
		for _, method := range methods {
			ops[method] = minimalOpenAPIOperation()
		}
		paths[path] = ops
	}
	body, _ := json.Marshal(map[string]any{"openapi": "3.0.3", "paths": paths})
	if missing := ValidateOpenAPI(body); len(missing) != 0 {
		t.Fatalf("unexpected missing operations: %v", missing)
	}
	delete(paths, "/panel/api/clients/list")
	body, _ = json.Marshal(map[string]any{"openapi": "3.0.3", "paths": paths})
	if missing := ValidateOpenAPI(body); len(missing) != 1 {
		t.Fatalf("expected one missing operation: %v", missing)
	}
	paths["/panel/api/clients/list"] = map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"content": map[string]any{"text/html": map[string]any{}}}}}}
	body, _ = json.Marshal(map[string]any{"openapi": "3.0.3", "paths": paths})
	if missing := ValidateOpenAPI(body); len(missing) != 1 || !strings.Contains(missing[0], "JSON success response") {
		t.Fatalf("expected incompatible response contract: %v", missing)
	}
}

func minimalOpenAPIOperation() map[string]any {
	return map[string]any{"responses": map[string]any{"200": map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}}}}
}

func TestEnvelopeValidationDistinguishesAPIFailure(t *testing.T) {
	body := []byte(`{"success":false,"msg":"upstream unavailable"}`)
	if err := ValidateEnvelope(body); err != nil {
		t.Fatalf("valid error envelope rejected: %v", err)
	}
	if _, err := DecodeEnvelope(body); err == nil {
		t.Fatal("API failure should not decode as evidence")
	}
}

func TestEmptyFallbackResolvesChildDefinedLater(t *testing.T) {
	body := envelope([]map[string]any{
		{"id": 1, "tag": "master", "protocol": "vless", "enable": true, "settings": map[string]any{"clients": []any{}, "fallbacks": []any{map[string]any{"childId": 2, "dest": ""}}}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}},
		{"id": 2, "tag": "child", "port": 8080, "protocol": "vmess", "enable": true, "settings": map[string]any{"clients": []any{}}, "streamSettings": map[string]any{"network": "ws", "security": "none"}},
	})
	inbounds, err := ParseInbounds(body)
	if err != nil {
		t.Fatal(err)
	}
	generated := map[string]any{"inbounds": []any{
		map[string]any{"tag": "master", "protocol": "vless", "streamSettings": map[string]any{"network": "tcp", "security": "none"}},
		map[string]any{"tag": "child", "protocol": "vmess", "streamSettings": map[string]any{"network": "ws", "security": "none"}},
	}}
	observations := ConfigObservations(inbounds, generated, redact.New([]byte(strings.Repeat("x", 32))), "panel-guid")
	for _, observation := range observations {
		if observation.RuleID == "CFG-001" {
			t.Fatalf("valid empty fallback rejected: %+v", observation)
		}
	}
}

func TestInvalidFallbackAndConfigDrift(t *testing.T) {
	body := envelope([]map[string]any{{"id": 1, "tag": "main", "protocol": "vless", "enable": true, "settings": map[string]any{"clients": []any{}, "fallbacks": []any{map[string]any{"childId": 99}}}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}}})
	inbounds, _ := ParseInbounds(body)
	observations := ConfigObservations(inbounds, map[string]any{"inbounds": []any{}}, redact.New([]byte(strings.Repeat("x", 32))), "panel-guid")
	got := map[string]bool{}
	for _, observation := range observations {
		got[observation.RuleID] = true
	}
	if !got["CFG-001"] || !got["CFG-003"] {
		t.Fatalf("missing expected observations: %v", got)
	}
}

func TestUnknownConfigurationSemanticsAreInconclusive(t *testing.T) {
	body := envelope([]map[string]any{{"id": 1, "tag": "future", "protocol": "future-protocol", "enable": true, "settings": map[string]any{"clients": []any{}}, "streamSettings": map[string]any{"network": "future-transport", "security": "future-security"}}})
	inbounds, _ := ParseInbounds(body)
	generated := map[string]any{"inbounds": []any{map[string]any{"tag": "future", "protocol": "future-protocol", "streamSettings": map[string]any{"network": "future-transport", "security": "future-security"}}}}
	observations := ConfigObservations(inbounds, generated, redact.New([]byte(strings.Repeat("x", 32))), "panel-guid")
	unknowns := 0
	for _, observation := range observations {
		if observation.RuleID == "CFG-002" && observation.Inconclusive && !observation.Blocking {
			unknowns++
		}
	}
	if unknowns != 3 {
		t.Fatalf("expected three inconclusive semantics, got %+v", observations)
	}
}

func TestNetworkIdentifierExtractionUsesAllowlist(t *testing.T) {
	body := envelope([]map[string]any{{
		"id": 1, "tag": "main", "protocol": "vless", "listen": "192.0.2.10", "enable": true,
		"settings": map[string]any{"clients": []any{map[string]any{"email": "secret@example.com"}}},
		"streamSettings": map[string]any{
			"network": "ws", "security": "reality",
			"wsSettings":      map[string]any{"headers": map[string]any{"Host": "edge.example.com"}},
			"realitySettings": map[string]any{"target": "origin.example.com:443", "privateKey": "must-not-escape"},
		},
	}})
	inbounds, err := ParseInbounds(body)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(inbounds[0].NetworkIdentifiers, ",")
	for _, expected := range []string{"192.0.2.10", "edge.example.com", "origin.example.com:443"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("missing network identifier %q in %q", expected, got)
		}
	}
	if strings.Contains(got, "must-not-escape") || strings.Contains(got, "secret@example.com") {
		t.Fatalf("non-network secret escaped allowlist: %q", got)
	}
}

func TestInboundConnectionStateExcludesTrafficCounters(t *testing.T) {
	base := map[string]any{"id": 1, "tag": "main", "protocol": "vless", "enable": true, "up": 10, "down": 20, "clientStats": []any{map[string]any{"up": 1}}, "settings": map[string]any{"clients": []any{}}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}}
	first, err := ParseInbounds(envelope([]map[string]any{base}))
	if err != nil {
		t.Fatal(err)
	}
	base["up"], base["down"], base["clientStats"] = 999, 888, []any{map[string]any{"up": 777}}
	second, err := ParseInbounds(envelope([]map[string]any{base}))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := CanonicalJSON(InboundConnectionState(first[0]))
	b, _ := CanonicalJSON(InboundConnectionState(second[0]))
	if string(a) != string(b) {
		t.Fatalf("volatile counters changed connection state:\n%s\n%s", a, b)
	}
}

func envelope(value any) []byte {
	body, _ := json.Marshal(map[string]any{"success": true, "obj": value})
	return body
}
