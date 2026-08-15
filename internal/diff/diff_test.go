package diff

import (
	"testing"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
)

func TestCompareDetectsMissingPanelAndConfigChange(t *testing.T) {
	before := model.Snapshot{Panels: []model.PanelSnapshot{
		{ID: "master", Alias: "panel_m", GeneratedConfigHash: "old", Inbounds: []model.InboundSnapshot{{Alias: "in_a", Protocol: "vless", SavedConfigHash: "old"}}},
		{ID: "node", Alias: "panel_n"},
	}}
	after := model.Snapshot{Panels: []model.PanelSnapshot{{ID: "master", Alias: "panel_m", GeneratedConfigHash: "new", Inbounds: []model.InboundSnapshot{{Alias: "in_a", Protocol: "vless", SavedConfigHash: "new"}}}}}
	changes, findings := Compare(before, after)
	if len(changes) < 3 || len(findings) < 2 {
		t.Fatalf("expected multiple regressions, got changes=%v findings=%v", changes, findings)
	}
	for _, change := range changes {
		if change.Field == "generated_config_hash" && change.Severity != "warning" {
			t.Fatalf("whole generated config drift should be warning evidence: %+v", change)
		}
	}
	for _, finding := range findings {
		if finding.Status != model.Fail {
			t.Fatalf("regression did not block: %+v", finding)
		}
	}
}
