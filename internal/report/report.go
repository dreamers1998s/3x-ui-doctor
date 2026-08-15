package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
)

func Render(format string, result model.Result) ([]byte, error) {
	switch strings.ToLower(format) {
	case "terminal":
		return terminal(result), nil
	case "json":
		body, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(body, '\n'), nil
	case "markdown":
		return markdown(result), nil
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

func terminal(result model.Result) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "3x-ui Doctor %s\n", result.Manifest.DoctorVersion)
	fmt.Fprintf(&b, "Readiness: %s\n", result.Readiness)
	if result.Manifest.TargetVersion != "" {
		fmt.Fprintf(&b, "Target: %s\n", result.Manifest.TargetVersion)
	}
	fmt.Fprintf(&b, "Panels: %d  Findings: %d  Changes: %d\n\n", panelCount(result), len(result.Findings), len(result.Changes))
	if result.Sensitive {
		b.WriteString("SENSITIVE: network identifiers are included.\n\n")
	}
	for _, finding := range sortedFindings(result.Findings) {
		fmt.Fprintf(&b, "%-12s %-13s %s", finding.Status, finding.RuleID, finding.Title)
		if finding.Subject != "" {
			fmt.Fprintf(&b, " [%s]", finding.Subject)
		}
		b.WriteByte('\n')
		if finding.Status != model.Pass {
			if finding.Observed != "" {
				fmt.Fprintf(&b, "  observed: %s\n", finding.Observed)
			}
			if finding.Expected != "" {
				fmt.Fprintf(&b, "  expected: %s\n", finding.Expected)
			}
			if finding.Remediation != "" {
				fmt.Fprintf(&b, "  remediation: %s\n", finding.Remediation)
			}
		}
	}
	return b.Bytes()
}

func markdown(result model.Result) []byte {
	var b bytes.Buffer
	b.WriteString("# 3x-ui Doctor report\n\n")
	fmt.Fprintf(&b, "- Readiness: **%s**\n", result.Readiness)
	fmt.Fprintf(&b, "- Doctor: `%s`\n", result.Manifest.DoctorVersion)
	if result.Manifest.TargetVersion != "" {
		fmt.Fprintf(&b, "- Target: `%s`\n", result.Manifest.TargetVersion)
	}
	fmt.Fprintf(&b, "- Started: `%s`\n", result.Manifest.StartedAt.Format("2006-01-02T15:04:05Z07:00"))
	if result.Sensitive {
		b.WriteString("- Classification: **SENSITIVE — network identifiers included**\n")
	}
	b.WriteString("\n## Findings\n\n")
	b.WriteString("| Status | Rule | Subject | Summary |\n|---|---|---|---|\n")
	for _, finding := range sortedFindings(result.Findings) {
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s |\n", finding.Status, finding.RuleID, escape(finding.Subject), escape(first(finding.Observed, finding.Evidence, finding.Title)))
	}
	if len(result.Changes) > 0 {
		b.WriteString("\n## Baseline changes\n\n| Severity | Panel | Field | Before | After |\n|---|---|---|---|---|\n")
		for _, change := range result.Changes {
			fmt.Fprintf(&b, "| %s | `%s` | `%s` | `%s` | `%s` |\n", change.Severity, escape(change.Panel), escape(change.Field), escape(short(change.Before)), escape(short(change.After)))
		}
	}
	b.WriteString("\n> Unofficial community project. Use only on systems you own or are authorized to manage.\n")
	return b.Bytes()
}

func sortedFindings(values []model.Finding) []model.Finding {
	out := append([]model.Finding(nil), values...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RuleID == out[j].RuleID {
			return out[i].Subject < out[j].Subject
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func panelCount(result model.Result) int { return result.PanelCount }

func escape(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "|", "\\|"), "\n", " ")
}
func short(value string) string {
	if len(value) > 20 {
		return value[:20] + "…"
	}
	return value
}
func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
