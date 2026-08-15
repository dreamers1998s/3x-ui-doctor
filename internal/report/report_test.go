package report

import (
	"strings"
	"testing"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
)

func TestReportsContainNoSeededSecrets(t *testing.T) {
	result := model.Result{SchemaVersion: 1, Readiness: model.Blocked, PanelCount: 2, Manifest: model.Manifest{DoctorVersion: "0.1.0", TargetVersion: "v3.6.0"}, Findings: []model.Finding{{RuleID: "API-001", Status: model.Fail, Title: "Contract", Subject: "panel_abcd", Observed: "timeout", Remediation: "retry"}}}
	secrets := []string{"token-secret", "alice@example.com", "550e8400-e29b-41d4-a716-446655440000", "sub-secret", "1.2.3.4"}
	for _, format := range []string{"terminal", "json", "markdown"} {
		body, err := Render(format, result)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if strings.Contains(string(body), secret) {
				t.Fatalf("%s leaked %q", format, secret)
			}
		}
	}
}

func TestSensitiveClassificationAppearsInEveryFormat(t *testing.T) {
	result := model.Result{SchemaVersion: 1, Readiness: model.Ready, Sensitive: true}
	for _, format := range []string{"terminal", "json", "markdown"} {
		body, err := Render(format, result)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.ToLower(string(body)), "sensitive") {
			t.Fatalf("%s did not mark sensitive output", format)
		}
	}
}
