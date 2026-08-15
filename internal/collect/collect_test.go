package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/adapter"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/config"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/redact"
)

func TestCollectorRedactsAndCapsSubscriptionsAtScale(t *testing.T) {
	const clientCount = 10_000
	clients := make([]map[string]any, 0, clientCount)
	for i := 0; i < clientCount; i++ {
		clients = append(clients, map[string]any{"id": i + 1, "email": fmt.Sprintf("user-%05d@example.com", i), "subId": fmt.Sprintf("subscription-%05d", i), "enable": true, "totalGB": 1 << 30, "expiryTime": int64(0), "inboundIds": []int{1}, "traffic": map[string]any{"up": i, "down": i, "enable": true}})
	}
	var linkRequests atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "panel-token-secret" && !strings.HasPrefix(token, "node-token-") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		isMaster := token == "panel-token-secret"
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/panel/api/openapi.json":
			paths := map[string]any{}
			for path, methods := range adapter.RequiredOpenAPIPaths {
				ops := map[string]any{}
				for _, method := range methods {
					ops[method] = map[string]any{"responses": map[string]any{"200": map[string]any{"content": map[string]any{"application/json": map[string]any{}}}}}
				}
				paths[path] = ops
			}
			writeJSON(w, map[string]any{"openapi": "3.0.3", "paths": paths})
		case r.URL.Path == "/panel/api/server/getPanelUpdateInfo":
			writeEnvelope(w, map[string]any{"currentVersion": "v3.5.0", "latestVersion": "v3.6.0"})
		case r.URL.Path == "/panel/api/server/status":
			writeEnvelope(w, map[string]any{"xray": map[string]any{"state": "running", "version": "v26.7.11"}})
		case r.URL.Path == "/panel/api/server/getConfigJson":
			writeEnvelope(w, map[string]any{"inbounds": []any{map[string]any{"tag": "in-1", "protocol": "vless", "streamSettings": map[string]any{"network": "tcp", "security": "none"}}}})
		case r.URL.Path == "/panel/api/inbounds/list":
			if isMaster {
				writeEnvelope(w, []any{map[string]any{"id": 1, "tag": "in-1", "protocol": "vless", "enable": true, "settings": map[string]any{"clients": []any{}}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}}})
			} else {
				writeEnvelope(w, []any{})
			}
		case r.URL.Path == "/panel/api/clients/list":
			if isMaster {
				writeEnvelope(w, clients)
			} else {
				writeEnvelope(w, []any{})
			}
		case r.URL.Path == "/panel/api/setting/all":
			writeEnvelope(w, map[string]any{"subEnable": false, "subJsonEnable": false, "subClashEnable": false})
		case r.URL.Path == "/panel/api/nodes/list":
			writeEnvelope(w, []any{
				map[string]any{"guid": "node-guid-1", "status": "online"},
				map[string]any{"guid": "node-guid-2", "status": "online"},
				map[string]any{"guid": "node-guid-3", "status": "online"},
				map[string]any{"guid": "node-guid-4", "status": "online"},
			})
		case strings.HasPrefix(r.URL.Path, "/panel/api/clients/links/") || strings.HasPrefix(r.URL.Path, "/panel/api/clients/subLinks/"):
			linkRequests.Add(1)
			writeEnvelope(w, []string{"vless://uuid@example.net:443?security=tls#redacted"})
		default:
			http.NotFound(w, r)
		}
	})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	pin := sha256.Sum256(server.Certificate().Raw)

	t.Setenv("PANEL_TOKEN", "panel-token-secret")
	for i := 1; i <= 4; i++ {
		t.Setenv(fmt.Sprintf("NODE_TOKEN_%d", i), fmt.Sprintf("node-token-%d", i))
	}
	t.Setenv("DOCTOR_KEY", strings.Repeat("h", 32))
	configPath := filepath.Join(t.TempDir(), "doctor.yaml")
	configBody := fmt.Sprintf(`
schema_version: 1
panels:
  - id: master
    role: master
    url: %s
    token_env: PANEL_TOKEN
    expected_guid: master-guid
    tls_pin_sha256: %s
  - {id: node-1, role: node, url: %s, token_env: NODE_TOKEN_1, expected_guid: node-guid-1, master_node_guid: node-guid-1, tls_pin_sha256: %s}
  - {id: node-2, role: node, url: %s, token_env: NODE_TOKEN_2, expected_guid: node-guid-2, master_node_guid: node-guid-2, tls_pin_sha256: %s}
  - {id: node-3, role: node, url: %s, token_env: NODE_TOKEN_3, expected_guid: node-guid-3, master_node_guid: node-guid-3, tls_pin_sha256: %s}
  - {id: node-4, role: node, url: %s, token_env: NODE_TOKEN_4, expected_guid: node-guid-4, master_node_guid: node-guid-4, tls_pin_sha256: %s}
redaction: {key_env: DOCTOR_KEY, key_id: test-key}
subscription: {sample_cap: 50}
`, server.URL, hex.EncodeToString(pin[:]), server.URL, hex.EncodeToString(pin[:]), server.URL, hex.EncodeToString(pin[:]), server.URL, hex.EncodeToString(pin[:]), server.URL, hex.EncodeToString(pin[:]))
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := New(runtime)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := collector.Collect(context.Background(), "preflight", "v3.6.0", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(snapshot.Panels[0].Subscriptions); got != 50 {
		t.Fatalf("sample cap not honored: got %d", got)
	}
	if got := len(snapshot.Panels); got != 5 {
		t.Fatalf("four-node topology not collected: got %d panels", got)
	}
	totalSamples := 0
	for _, panel := range snapshot.Panels {
		totalSamples += len(panel.Subscriptions)
	}
	if totalSamples != 50 {
		t.Fatalf("global sample cap not honored: got %d", totalSamples)
	}
	if got := linkRequests.Load(); got != 100 {
		t.Fatalf("unexpected link request count: %d", got)
	}
	body, _ := json.Marshal(snapshot)
	for _, secret := range []string{"panel-token-secret", "user-00000@example.com", "subscription-00000", "uuid@example.net"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("snapshot leaked %q", secret)
		}
	}
}

func TestFetchClassifiesUnsafeResponses(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		status      int
		body        string
		blocking    bool
		unknown     bool
	}{
		{name: "empty", contentType: "application/json", status: 200, blocking: true},
		{name: "media type", contentType: "text/html", status: 200, body: `{}`, blocking: true},
		{name: "invalid envelope", contentType: "application/json", status: 200, body: `{"ok":true}`, blocking: true},
		{name: "authentication", contentType: "application/json", status: 401, body: `{"success":false}`, unknown: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			pin := sha256.Sum256(server.Certificate().Raw)
			runtime := &config.Runtime{
				Config: config.Config{Panels: []config.Panel{{ID: "master", Role: model.RoleMaster, URL: server.URL, ExpectedGUID: "master-guid", TLSPinSHA256: hex.EncodeToString(pin[:])}}, Transport: config.Transport{}},
				Tokens: map[string]string{"master": "secret"}, RequestTimeout: time.Second,
				RedactionKey: []byte(strings.Repeat("h", 32)),
			}
			collector, err := New(runtime)
			if err != nil {
				t.Fatal(err)
			}
			work := panelWork{safe: model.PanelSnapshot{Alias: "panel_test"}}
			if body := collector.fetch(context.Background(), &work, collector.clients["master"], "/panel/api/server/status", true); body != nil {
				t.Fatal("unsafe response was accepted as evidence")
			}
			if len(work.safe.Observations) != 1 || work.safe.Observations[0].Blocking != tc.blocking || work.safe.Observations[0].Inconclusive != tc.unknown {
				t.Fatalf("unexpected classification: %+v", work.safe.Observations)
			}
		})
	}
}

func TestUnknownVersionUsesCompatibilityMode(t *testing.T) {
	var versionSpecificRequests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/panel/api/openapi.json":
			writeJSON(w, map[string]any{"openapi": "3.0.3", "paths": map[string]any{}})
		case "/panel/api/server/getPanelUpdateInfo":
			writeEnvelope(w, map[string]any{"currentVersion": "v4.0.0"})
		case "/panel/api/server/status":
			writeEnvelope(w, map[string]any{"xray": map[string]any{"state": "running", "version": "v27.0.0"}})
		default:
			versionSpecificRequests.Add(1)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	pin := sha256.Sum256(server.Certificate().Raw)
	runtime := &config.Runtime{
		Config: config.Config{Panels: []config.Panel{{ID: "master", Role: model.RoleMaster, URL: server.URL, ExpectedGUID: "master-guid", TLSPinSHA256: hex.EncodeToString(pin[:])}}, Redaction: config.Redaction{KeyID: "test"}, Subscription: config.Subscription{SampleCap: 50}, Transport: config.Transport{PanelConcurrency: 1}},
		Tokens: map[string]string{"master": "secret"}, RequestTimeout: time.Second,
		RedactionKey: []byte(strings.Repeat("h", 32)),
	}
	collector, err := New(runtime)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := collector.Collect(context.Background(), "check", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if versionSpecificRequests.Load() != 0 {
		t.Fatalf("compatibility mode made %d version-specific requests", versionSpecificRequests.Load())
	}
	if snapshot.Panels[0].PanelVersion != "v4.0.0" || len(snapshot.Panels[0].Inbounds) != 0 {
		t.Fatalf("unexpected compatibility snapshot: %+v", snapshot.Panels[0])
	}
}

func TestTopologyDetectsNodeGUIDMismatch(t *testing.T) {
	runtime := &config.Runtime{Config: config.Config{}, RedactionKey: []byte(strings.Repeat("h", 32))}
	collector := &Collector{runtime: runtime, redactor: redact.New(runtime.RedactionKey)}
	works := []panelWork{
		{config: config.Panel{ID: "master", Role: model.RoleMaster, ExpectedGUID: "master-guid"}, raw: adapter.ParsedPanel{Nodes: []adapter.RawNode{{GUID: "node-guid", Status: "online"}}}, safe: model.PanelSnapshot{Alias: "master"}, supported: true},
		{config: config.Panel{ID: "node", Role: model.RoleNode, ExpectedGUID: "wrong-guid", MasterNodeGUID: "node-guid"}, safe: model.PanelSnapshot{Alias: "node"}, supported: true},
	}
	collector.reconcileTopology(works, "", "check")
	for _, observation := range works[0].safe.Observations {
		if observation.Kind == "node_identity_mismatch" && observation.Blocking {
			return
		}
	}
	t.Fatal("node GUID mismatch was not blocking")
}

func TestTopologyReportsXrayVersionSkewAsWarningEvidence(t *testing.T) {
	runtime := &config.Runtime{Config: config.Config{}, RedactionKey: []byte(strings.Repeat("h", 32))}
	collector := &Collector{runtime: runtime, redactor: redact.New(runtime.RedactionKey)}
	works := []panelWork{
		{config: config.Panel{ID: "master", Role: model.RoleMaster, ExpectedGUID: "master-guid"}, raw: adapter.ParsedPanel{Nodes: []adapter.RawNode{{GUID: "node-guid", Status: "online"}}}, safe: model.PanelSnapshot{Alias: "master", XrayVersion: "v26.1.0"}, supported: true},
		{config: config.Panel{ID: "node", Role: model.RoleNode, ExpectedGUID: "node-guid", MasterNodeGUID: "node-guid"}, safe: model.PanelSnapshot{Alias: "node", XrayVersion: "v26.2.0"}, supported: true},
	}
	collector.reconcileTopology(works, "", "check")
	for _, observation := range works[0].safe.Observations {
		if observation.Kind == "xray_version_skew" && !observation.Blocking && !observation.Inconclusive {
			return
		}
	}
	t.Fatal("Xray version skew warning evidence was not emitted")
}

func writeEnvelope(w http.ResponseWriter, value any) {
	writeJSON(w, map[string]any{"success": true, "obj": value})
}
func writeJSON(w http.ResponseWriter, value any) { _ = json.NewEncoder(w).Encode(value) }

var _ = time.Second
