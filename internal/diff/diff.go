package diff

import (
	"fmt"
	"sort"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
)

func Compare(before, after model.Snapshot) ([]model.Change, []model.Finding) {
	beforePanels := map[string]model.PanelSnapshot{}
	afterPanels := map[string]model.PanelSnapshot{}
	for _, panel := range before.Panels {
		beforePanels[panel.ID] = panel
	}
	for _, panel := range after.Panels {
		afterPanels[panel.ID] = panel
	}
	var changes []model.Change
	var findings []model.Finding
	for id, oldPanel := range beforePanels {
		newPanel, ok := afterPanels[id]
		if !ok {
			changes = append(changes, change(id, "panel", "present", "missing", "error"))
			findings = append(findings, regression("NODE-003", oldPanel.Alias, "panel missing after upgrade", "same configured topology"))
			continue
		}
		compareField := func(field, oldValue, newValue, severity string) {
			if oldValue != newValue {
				changes = append(changes, change(id, field, oldValue, newValue, severity))
			}
		}
		compareField("panel_version", oldPanel.PanelVersion, newPanel.PanelVersion, "info")
		compareField("xray_version", oldPanel.XrayVersion, newPanel.XrayVersion, "info")
		compareField("openapi_hash", oldPanel.OpenAPIHash, newPanel.OpenAPIHash, "warning")
		if oldPanel.GeneratedConfigHash != "" && newPanel.GeneratedConfigHash != "" && oldPanel.GeneratedConfigHash != newPanel.GeneratedConfigHash {
			changes = append(changes, change(id, "generated_config_hash", oldPanel.GeneratedConfigHash, newPanel.GeneratedConfigHash, "warning"))
		}
		compareObjectSets(id, "inbound", inboundMap(oldPanel.Inbounds), inboundMap(newPanel.Inbounds), "CFG-003", &changes, &findings)
		compareObjectSets(id, "client", clientMap(oldPanel.Clients), clientMap(newPanel.Clients), "NODE-003", &changes, &findings)
		compareSubscriptions(id, oldPanel.Subscriptions, newPanel.Subscriptions, &changes, &findings)
	}
	for id, panel := range afterPanels {
		if _, ok := beforePanels[id]; !ok {
			changes = append(changes, change(id, "panel", "missing", "present", "error"))
			findings = append(findings, regression("NODE-003", panel.Alias, "unexpected panel appeared after upgrade", "same configured topology"))
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Panel == changes[j].Panel {
			return changes[i].Field < changes[j].Field
		}
		return changes[i].Panel < changes[j].Panel
	})
	return changes, findings
}

func compareObjectSets(panelID, kind string, before, after map[string]string, ruleID string, changes *[]model.Change, findings *[]model.Finding) {
	for alias, oldHash := range before {
		newHash, ok := after[alias]
		if !ok {
			*changes = append(*changes, change(panelID, kind+":"+alias, "present", "missing", "error"))
			*findings = append(*findings, regression(ruleID, alias, kind+" missing after upgrade", "stable anonymous object set"))
		} else if oldHash != newHash {
			*changes = append(*changes, change(panelID, kind+":"+alias, oldHash, newHash, "error"))
			*findings = append(*findings, regression(ruleID, alias, kind+" connection state changed", "stable connection-relevant state"))
		}
	}
	for alias := range after {
		if _, ok := before[alias]; !ok {
			*changes = append(*changes, change(panelID, kind+":"+alias, "missing", "present", "error"))
			*findings = append(*findings, regression(ruleID, alias, "unexpected "+kind+" appeared after upgrade", "stable anonymous object set"))
		}
	}
}

func compareSubscriptions(panelID string, before, after []model.SubscriptionObservation, changes *[]model.Change, findings *[]model.Finding) {
	oldValues, newValues := map[string]string{}, map[string]string{}
	for _, value := range before {
		oldValues[value.ClientAlias+":"+value.Format] = fmt.Sprint(value.Parsed, value.SemanticSet)
	}
	for _, value := range after {
		newValues[value.ClientAlias+":"+value.Format] = fmt.Sprint(value.Parsed, value.SemanticSet)
	}
	compareObjectSets(panelID, "subscription", oldValues, newValues, "SUB-003", changes, findings)
}

func inboundMap(values []model.InboundSnapshot) map[string]string {
	result := map[string]string{}
	for _, value := range values {
		result[value.Alias] = fmt.Sprintf("%s|%s|%s|%s|%t|%s", value.Protocol, value.Network, value.Security, value.Flow, value.Enabled, value.SavedConfigHash)
	}
	return result
}

func clientMap(values []model.ClientSnapshot) map[string]string {
	result := map[string]string{}
	for _, value := range values {
		result[value.Alias] = fmt.Sprintf("%t|%d|%d|%v", value.Enabled, value.TotalBytes, value.ExpiryUnixMS, value.InboundAliases)
	}
	return result
}

func change(panel, field, before, after, severity string) model.Change {
	return model.Change{Panel: panel, Field: field, Before: before, After: after, Severity: severity}
}

func regression(ruleID, subject, observed, expected string) model.Finding {
	return model.Finding{SchemaVersion: model.FindingSchemaVersion, RuleID: ruleID, Status: model.Fail, Title: "Upgrade regression", Subject: subject, Observed: observed, Expected: expected, Evidence: "baseline comparison", Impact: "The upgrade changed audited state unexpectedly.", Remediation: "Review the anonymous diff and restore or intentionally accept the change before proceeding."}
}
