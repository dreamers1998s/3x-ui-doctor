package rules

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
)

type Options struct {
	RelativeThreshold float64
	AbsoluteThreshold int64
	LimitGrace        time.Duration
}

var order = []string{"API-001", "API-003", "CFG-001", "CFG-002", "CFG-003", "SUB-001", "SUB-003", "NODE-001", "NODE-003", "TRAFFIC-001", "TRAFFIC-002", "LIMIT-001"}

type meta struct {
	title, impact, remediation string
}

var metadata = map[string]meta{
	"API-001":     {"Safe API response contract", "Automation cannot trust or interpret panel state.", "Inspect the panel API and authentication path; do not continue an upgrade until reads are stable."},
	"API-003":     {"OpenAPI compatibility", "Doctor or other automation may call an endpoint with incompatible semantics.", "Review the reported operation against the target release OpenAPI document."},
	"CFG-001":     {"Fallback target resolution", "Xray may reject the generated listener or route traffic to no destination.", "Set an explicit destination or repair the referenced child inbound."},
	"CFG-002":     {"Target configuration compatibility", "The target Xray/panel combination may reject or strip this configuration.", "Complete or change the protocol, transport, security, and flow combination before upgrading."},
	"CFG-003":     {"Saved and generated configuration consistency", "The running Xray configuration may not represent the panel state.", "Compare the anonymous inbound evidence and regenerate only after reviewing panel logs."},
	"SUB-001":     {"Subscription round-trip parsing", "Client applications may be unable to import the generated subscription.", "Regenerate the subscription and inspect the affected format and inbound combination."},
	"SUB-003":     {"Share and subscription consistency", "Users may receive connection settings different from the panel share view.", "Compare the affected format and regenerate the subscription after reviewing host overrides."},
	"NODE-001":    {"Required node health and identity", "A complete multi-node audit cannot be trusted or a node is on the wrong version.", "Restore node reachability, verify its GUID, token, TLS identity, and target version, then rerun Doctor."},
	"NODE-003":    {"Assigned object consistency", "A node may be missing or serving an unexpected inbound/client assignment.", "Review the master sync scope and reconcile the affected anonymous object."},
	"TRAFFIC-001": {"Repeated traffic accumulation", "A client quota may be consumed repeatedly without equivalent node traffic.", "Pause the upgrade and inspect node traffic baselines and synchronization state."},
	"TRAFFIC-002": {"Persistent cross-node traffic deviation", "Traffic and quota decisions may differ between master and nodes.", "Review per-node counters and synchronization latency before changing limits."},
	"LIMIT-001":   {"Quota and enable-state consistency", "An expired or depleted client remains enabled in panel state.", "Confirm reset policy and synchronization, then disable or repair the client through 3x-ui."},
}

func Evaluate(snapshot model.Snapshot, opts Options) []model.Finding {
	byRule := map[string][]model.Finding{}
	for _, panel := range snapshot.Panels {
		for _, observation := range panel.Observations {
			status := model.Warn
			if observation.Blocking {
				status = model.Fail
			} else if observation.Inconclusive {
				status = model.Unknown
			}
			byRule[observation.RuleID] = append(byRule[observation.RuleID], fromObservation(observation, status))
		}
	}
	evaluateVersionSupport(snapshot, byRule)
	evaluateConfigEvidence(snapshot, byRule)
	evaluateSubscriptions(snapshot, byRule)
	evaluateTraffic(snapshot, opts, byRule)
	evaluateLimits(snapshot, opts, byRule)

	var findings []model.Finding
	for _, ruleID := range order {
		items := byRule[ruleID]
		if len(items) == 0 {
			m := metadata[ruleID]
			items = []model.Finding{{RuleID: ruleID, Status: model.Pass, Title: m.title, Evidence: "No violation found in collected evidence."}}
		}
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Status == items[j].Status {
				return items[i].Subject < items[j].Subject
			}
			return statusRank(items[i].Status) > statusRank(items[j].Status)
		})
		findings = append(findings, items...)
	}
	for i := range findings {
		findings[i].SchemaVersion = model.FindingSchemaVersion
	}
	return findings
}

func Readiness(findings []model.Finding) model.Readiness {
	hasUnknown := false
	for _, finding := range findings {
		if finding.Status == model.Fail {
			return model.Blocked
		}
		if finding.Status == model.Unknown {
			hasUnknown = true
		}
	}
	if hasUnknown {
		return model.Inconclusive
	}
	return model.Ready
}

func fromObservation(observation model.Observation, status model.RuleStatus) model.Finding {
	m := metadata[observation.RuleID]
	return model.Finding{RuleID: observation.RuleID, Status: status, Title: m.title, Subject: observation.Subject, Observed: observation.Observed, Expected: observation.Expected, Evidence: first(observation.Evidence, observation.Kind), Impact: m.impact, Remediation: m.remediation}
}

func evaluateVersionSupport(snapshot model.Snapshot, byRule map[string][]model.Finding) {
	for _, panel := range snapshot.Panels {
		version := panel.PanelVersion
		if version == "" {
			byRule["API-003"] = append(byRule["API-003"], finding("API-003", model.Unknown, panel.Alias, "panel version is unknown", "v3.5.0 or v3.6.0", "version evidence missing"))
		} else if version != "v3.5.0" && version != "v3.6.0" {
			byRule["API-003"] = append(byRule["API-003"], finding("API-003", model.Unknown, panel.Alias, version, "v3.5.0 or v3.6.0", "compatibility mode"))
		}
	}
}

func evaluateConfigEvidence(snapshot model.Snapshot, byRule map[string][]model.Finding) {
	for _, panel := range snapshot.Panels {
		if panel.GeneratedConfigHash == "" || panel.Inbounds == nil {
			for _, ruleID := range []string{"CFG-001", "CFG-002", "CFG-003"} {
				byRule[ruleID] = append(byRule[ruleID], finding(ruleID, model.Unknown, panel.Alias, "configuration evidence incomplete", "saved and generated configuration", "collector evidence missing"))
			}
		}
	}
}

func evaluateSubscriptions(snapshot model.Snapshot, byRule map[string][]model.Finding) {
	seen := false
	for _, panel := range snapshot.Panels {
		for _, observation := range panel.Subscriptions {
			seen = true
			if !observation.Parsed {
				status := model.Fail
				if observation.ErrorCode == "api_evidence_missing" || observation.ErrorCode == "request_error" || observation.ErrorCode == "timeout" || observation.ErrorCode == "external host is not allowlisted" {
					status = model.Unknown
				}
				byRule["SUB-001"] = append(byRule["SUB-001"], finding("SUB-001", status, observation.ClientAlias, observation.ErrorCode, "parseable "+observation.Format+" subscription", observation.Stratum))
				continue
			}
			if len(observation.ShareSet) > 0 && !equalStrings(observation.ShareSet, observation.SemanticSet) {
				byRule["SUB-003"] = append(byRule["SUB-003"], finding("SUB-003", model.Fail, observation.ClientAlias, "semantic link sets differ", "equivalent connection-relevant fields", observation.Stratum))
			}
		}
	}
	if !seen {
		for _, ruleID := range []string{"SUB-001", "SUB-003"} {
			byRule[ruleID] = append(byRule[ruleID], finding(ruleID, model.Unknown, "", "no eligible subscription sample", "at least one deterministic sample", "subscription evidence unavailable"))
		}
	}
}

func evaluateTraffic(snapshot model.Snapshot, opts Options, byRule map[string][]model.Finding) {
	var master *model.PanelSnapshot
	var nodes []model.PanelSnapshot
	for i := range snapshot.Panels {
		if snapshot.Panels[i].Role == model.RoleMaster {
			master = &snapshot.Panels[i]
		} else {
			nodes = append(nodes, snapshot.Panels[i])
		}
	}
	if master == nil || len(nodes) == 0 {
		return
	}
	masterSeries := trafficSeries(master.Traffic)
	clientByAlias := map[string]model.ClientSnapshot{}
	originByInbound := map[string]string{}
	for _, inbound := range master.Inbounds {
		originByInbound[inbound.Alias] = inbound.OriginGUIDAlias
	}
	for _, client := range master.Clients {
		clientByAlias[client.Alias] = client
	}
	nodeSeries := map[string][][]int64{}
	for _, node := range nodes {
		for alias, series := range trafficSeries(node.Traffic) {
			nodeSeries[alias] = append(nodeSeries[alias], series)
		}
	}
	validEvidence := false
	for alias, m := range masterSeries {
		client, ok := clientByAlias[alias]
		if !ok || !isNodeOnlyClient(client, originByInbound, master.GUIDAlias) {
			continue
		}
		series := nodeSeries[alias]
		if len(m) < 4 || len(series) == 0 {
			continue
		}
		validEvidence = true
		n := sumSeries(series)
		count := min(len(m), len(n))
		if count < 4 {
			continue
		}
		masterDeltas, nodeDeltas := deltas(m[:count]), deltas(n[:count])
		if repeatedMasterDelta(masterDeltas, nodeDeltas) {
			byRule["TRAFFIC-001"] = append(byRule["TRAFFIC-001"], finding("TRAFFIC-001", model.Fail, alias, "repeated positive master delta while nodes remain unchanged", "master delta follows source node traffic", "three consecutive intervals"))
		}
		consecutive := 0
		for i := 0; i < count; i++ {
			maxValue := max64(abs64(m[i]), abs64(n[i]))
			threshold := max64(opts.AbsoluteThreshold, int64(float64(maxValue)*opts.RelativeThreshold))
			if abs64(m[i]-n[i]) > threshold {
				consecutive++
				if consecutive == 1 {
					byRule["TRAFFIC-002"] = append(byRule["TRAFFIC-002"], finding("TRAFFIC-002", model.Warn, alias, "single sample exceeded configured deviation", fmt.Sprintf("within %d bytes", threshold), "transient sample"))
				}
				if consecutive >= 3 {
					byRule["TRAFFIC-002"] = append(byRule["TRAFFIC-002"], finding("TRAFFIC-002", model.Fail, alias, fmt.Sprintf("persistent deviation exceeds %d bytes", threshold), "master and summed node counters within threshold", "three consecutive samples"))
					break
				}
			} else {
				consecutive = 0
			}
		}
	}
	if !validEvidence {
		for _, ruleID := range []string{"TRAFFIC-001", "TRAFFIC-002"} {
			byRule[ruleID] = append(byRule[ruleID], finding(ruleID, model.Unknown, "", "fewer than four aligned master/node samples", "at least four aligned samples", "traffic observation incomplete"))
		}
	}
}

func evaluateLimits(snapshot model.Snapshot, opts Options, byRule map[string][]model.Finding) {
	now := snapshot.Manifest.FinishedAt
	seenEvidence := false
	for _, panel := range snapshot.Panels {
		series := trafficObservations(panel.Traffic)
		for _, client := range panel.Clients {
			values := series[client.Alias]
			if len(values) < 3 {
				continue
			}
			seenEvidence = true
			lastThree := values[len(values)-3:]
			expired := client.ExpiryUnixMS > 0 && now.After(time.UnixMilli(client.ExpiryUnixMS).Add(opts.LimitGrace))
			depleted := client.TotalBytes > 0
			enabledPersisted := client.Enabled
			for _, value := range lastThree {
				depleted = depleted && value.Up+value.Down >= client.TotalBytes
				enabledPersisted = enabledPersisted && value.Enabled
			}
			if enabledPersisted && (expired || depleted) {
				reason := "quota depleted"
				if expired {
					reason = "expiry passed beyond grace"
				}
				byRule["LIMIT-001"] = append(byRule["LIMIT-001"], finding("LIMIT-001", model.Fail, client.Alias, reason+" while enabled", "disabled client after effective limit", "state persisted across observation window"))
			}
		}
	}
	if !seenEvidence {
		byRule["LIMIT-001"] = append(byRule["LIMIT-001"], finding("LIMIT-001", model.Unknown, "", "fewer than three samples", "three limit observations", "limit evidence incomplete"))
	}
}

func finding(ruleID string, status model.RuleStatus, subject, observed, expected, evidence string) model.Finding {
	m := metadata[ruleID]
	return model.Finding{RuleID: ruleID, Status: status, Title: m.title, Subject: subject, Observed: observed, Expected: expected, Evidence: evidence, Impact: m.impact, Remediation: m.remediation}
}

func trafficSeries(observations []model.TrafficObservation) map[string][]int64 {
	grouped := trafficObservations(observations)
	out := map[string][]int64{}
	for alias, items := range grouped {
		sort.Slice(items, func(i, j int) bool { return items[i].At.Before(items[j].At) })
		for _, item := range items {
			out[alias] = append(out[alias], item.Up+item.Down)
		}
	}
	return out
}

func trafficObservations(observations []model.TrafficObservation) map[string][]model.TrafficObservation {
	grouped := map[string][]model.TrafficObservation{}
	for _, observation := range observations {
		grouped[observation.ClientAlias] = append(grouped[observation.ClientAlias], observation)
	}
	for alias := range grouped {
		sort.Slice(grouped[alias], func(i, j int) bool { return grouped[alias][i].At.Before(grouped[alias][j].At) })
	}
	return grouped
}

func isNodeOnlyClient(client model.ClientSnapshot, originByInbound map[string]string, masterGUIDAlias string) bool {
	if len(client.InboundAliases) == 0 {
		return false
	}
	for _, inboundAlias := range client.InboundAliases {
		origin := originByInbound[inboundAlias]
		if origin == "" || origin == masterGUIDAlias {
			return false
		}
	}
	return true
}

func sumSeries(series [][]int64) []int64 {
	maxLen := 0
	for _, values := range series {
		if len(values) > maxLen {
			maxLen = len(values)
		}
	}
	out := make([]int64, maxLen)
	for _, values := range series {
		for i, value := range values {
			out[i] += value
		}
	}
	return out
}

func deltas(values []int64) []int64 {
	result := make([]int64, 0, len(values)-1)
	for i := 1; i < len(values); i++ {
		result = append(result, values[i]-values[i-1])
	}
	return result
}

func repeatedMasterDelta(master, node []int64) bool {
	if len(master) < 3 || len(node) < 3 {
		return false
	}
	for start := 0; start+2 < len(master) && start+2 < len(node); start++ {
		base := master[start]
		if base <= 0 {
			continue
		}
		tolerance := math.Max(1, math.Abs(float64(base))*0.01)
		ok := true
		for i := start; i < start+3; i++ {
			if math.Abs(float64(master[i]-base)) > tolerance || abs64(node[i]) > 65536 {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func statusRank(status model.RuleStatus) int {
	switch status {
	case model.Fail:
		return 4
	case model.Unknown:
		return 3
	case model.Warn:
		return 2
	default:
		return 1
	}
}

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
