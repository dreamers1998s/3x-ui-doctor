package rules

import (
	"testing"
	"time"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
)

func TestReadinessPrecedence(t *testing.T) {
	if got := Readiness([]model.Finding{{Status: model.Warn}}); got != model.Ready {
		t.Fatalf("got %s", got)
	}
	if got := Readiness([]model.Finding{{Status: model.Unknown}}); got != model.Inconclusive {
		t.Fatalf("got %s", got)
	}
	if got := Readiness([]model.Finding{{Status: model.Unknown}, {Status: model.Fail}}); got != model.Blocked {
		t.Fatalf("got %s", got)
	}
}

func TestUnknownVersionIsInconclusive(t *testing.T) {
	snapshot := baseSnapshot()
	snapshot.Panels[0].PanelVersion = "v4.0.0"
	findings := Evaluate(snapshot, Options{RelativeThreshold: .05, AbsoluteThreshold: 64 << 20, LimitGrace: 30 * time.Second})
	if !hasFinding(findings, "API-003", model.Unknown) {
		t.Fatal("unknown panel version was not inconclusive")
	}
	for _, finding := range findings {
		if finding.SchemaVersion != model.FindingSchemaVersion {
			t.Fatalf("finding %s has schema version %d", finding.RuleID, finding.SchemaVersion)
		}
	}
}

func TestTrafficCompoundingAndDeviation(t *testing.T) {
	now := time.Now().UTC()
	snapshot := baseSnapshot()
	snapshot.Panels = []model.PanelSnapshot{
		{ID: "master", Role: model.RoleMaster, Alias: "panel_master", GUIDAlias: "guid_master", PanelVersion: "v3.5.0", GeneratedConfigHash: "g", Inbounds: []model.InboundSnapshot{{Alias: "in_node", OriginGUIDAlias: "guid_node"}}, Clients: []model.ClientSnapshot{{Alias: "client_x", InboundAliases: []string{"in_node"}}}, Traffic: traffic("client_x", now, []int64{0, 100, 200, 300, 400, 500})},
		{ID: "node", Role: model.RoleNode, Alias: "panel_node", PanelVersion: "v3.5.0", GeneratedConfigHash: "g", Inbounds: []model.InboundSnapshot{}, Traffic: traffic("client_x", now, []int64{0, 0, 0, 0, 0, 0})},
	}
	findings := Evaluate(snapshot, Options{RelativeThreshold: .05, AbsoluteThreshold: 10, LimitGrace: 0})
	if !hasFinding(findings, "TRAFFIC-001", model.Fail) {
		t.Fatal("compounding traffic not detected")
	}
	if !hasFinding(findings, "TRAFFIC-002", model.Fail) {
		t.Fatal("persistent deviation not detected")
	}
}

func TestTrafficAuditSkipsMasterLocalClients(t *testing.T) {
	now := time.Now().UTC()
	snapshot := baseSnapshot()
	snapshot.Panels = []model.PanelSnapshot{
		{ID: "master", Role: model.RoleMaster, Alias: "panel_master", GUIDAlias: "guid_master", PanelVersion: "v3.5.0", GeneratedConfigHash: "g", Inbounds: []model.InboundSnapshot{{Alias: "in_local", OriginGUIDAlias: "guid_master"}}, Clients: []model.ClientSnapshot{{Alias: "client_x", InboundAliases: []string{"in_local"}}}, Traffic: traffic("client_x", now, []int64{0, 100, 200, 300})},
		{ID: "node", Role: model.RoleNode, Alias: "panel_node", PanelVersion: "v3.5.0", GeneratedConfigHash: "g", Inbounds: []model.InboundSnapshot{}, Traffic: traffic("client_x", now, []int64{0, 0, 0, 0})},
	}
	findings := Evaluate(snapshot, Options{RelativeThreshold: .05, AbsoluteThreshold: 10})
	if hasFinding(findings, "TRAFFIC-002", model.Fail) {
		t.Fatal("master-local client was compared to child nodes")
	}
}

func TestLimitAndSubscriptionFailures(t *testing.T) {
	now := time.Now().UTC()
	snapshot := baseSnapshot()
	snapshot.Panels[0].Clients = []model.ClientSnapshot{{Alias: "client_x", Enabled: true, TotalBytes: 100, UsedBytes: 100}}
	snapshot.Panels[0].Traffic = traffic("client_x", now, []int64{100, 100, 100})
	snapshot.Panels[0].Subscriptions = []model.SubscriptionObservation{{ClientAlias: "client_x", Format: "raw", Parsed: true, ShareSet: []string{"a"}, SemanticSet: []string{"b"}}}
	findings := Evaluate(snapshot, Options{RelativeThreshold: .05, AbsoluteThreshold: 10, LimitGrace: 0})
	if !hasFinding(findings, "LIMIT-001", model.Fail) {
		t.Fatal("enabled depleted client not detected")
	}
	if !hasFinding(findings, "SUB-003", model.Fail) {
		t.Fatal("subscription mismatch not detected")
	}
}

func TestLimitRequiresPersistentlyEnabledSamples(t *testing.T) {
	now := time.Now().UTC()
	snapshot := baseSnapshot()
	snapshot.Panels[0].Clients = []model.ClientSnapshot{{Alias: "client_x", Enabled: true, TotalBytes: 100}}
	snapshot.Panels[0].Traffic = traffic("client_x", now, []int64{100, 100, 100})
	snapshot.Panels[0].Traffic[2].Enabled = false
	findings := Evaluate(snapshot, Options{RelativeThreshold: .05, AbsoluteThreshold: 10})
	if hasFinding(findings, "LIMIT-001", model.Fail) {
		t.Fatal("limit rule ignored a disabled read-back sample")
	}
}

func baseSnapshot() model.Snapshot {
	return model.Snapshot{SchemaVersion: 1, Manifest: model.Manifest{FinishedAt: time.Now().UTC()}, Panels: []model.PanelSnapshot{{ID: "master", Role: model.RoleMaster, Alias: "panel_master", PanelVersion: "v3.5.0", GeneratedConfigHash: "g", Inbounds: []model.InboundSnapshot{}}}}
}

func traffic(alias string, start time.Time, values []int64) []model.TrafficObservation {
	result := make([]model.TrafficObservation, len(values))
	for i, value := range values {
		result[i] = model.TrafficObservation{ClientAlias: alias, At: start.Add(time.Duration(i) * time.Second), Up: value, Enabled: true}
	}
	return result
}

func hasFinding(findings []model.Finding, ruleID string, status model.RuleStatus) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID && finding.Status == status {
			return true
		}
	}
	return false
}
