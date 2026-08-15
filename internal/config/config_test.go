package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGitHubWorkflowYAMLParses(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("workflow discovery failed: %v", err)
	}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := yaml.Unmarshal(body, &document); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if document["jobs"] == nil {
			t.Errorf("%s: missing jobs", path)
		}
	}
}

func TestLoadDefaultsAndSecrets(t *testing.T) {
	t.Setenv("MASTER_TOKEN", "token-secret")
	t.Setenv("DOCTOR_HMAC", strings.Repeat("k", 32))
	path := writeConfig(t, `
schema_version: 1
panels:
  - id: master
    role: master
    url: https://panel.example/base
    token_env: MASTER_TOKEN
    expected_guid: 11111111-1111-1111-1111-111111111111
redaction:
  key_env: DOCTOR_HMAC
  key_id: production-v1
`)
	runtime, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Config.Subscription.SampleCap != 50 || runtime.RequestTimeout.String() != "10s" {
		t.Fatalf("defaults missing: %+v", runtime.Config)
	}
	if runtime.Tokens["master"] != "token-secret" {
		t.Fatal("token was not resolved")
	}
}

func TestLoadRejectsInlineUnknownSecretAndHTTP(t *testing.T) {
	t.Setenv("MASTER_TOKEN", "token-secret")
	t.Setenv("DOCTOR_HMAC", strings.Repeat("k", 32))
	path := writeConfig(t, `
schema_version: 1
panels:
  - id: master
    role: master
    url: http://panel.example
    token_env: MASTER_TOKEN
    token: should-not-be-accepted
    expected_guid: guid
redaction: {key_env: DOCTOR_HMAC, key_id: test}
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected strict configuration rejection")
	}
}

func TestLoadRequiresNodeMapping(t *testing.T) {
	t.Setenv("MASTER_TOKEN", "token-secret")
	t.Setenv("NODE_TOKEN", "node-secret")
	t.Setenv("DOCTOR_HMAC", strings.Repeat("k", 32))
	path := writeConfig(t, `
schema_version: 1
panels:
  - {id: master, role: master, url: https://master.example, token_env: MASTER_TOKEN, expected_guid: master-guid}
  - {id: node, role: node, url: https://node.example, token_env: NODE_TOKEN, expected_guid: node-guid}
redaction: {key_env: DOCTOR_HMAC, key_id: test}
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "master_node_guid") {
		t.Fatalf("expected node mapping error, got %v", err)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "doctor.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
