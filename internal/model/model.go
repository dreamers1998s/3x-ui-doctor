package model

import "time"

const (
	SnapshotSchemaVersion = 1
	ResultSchemaVersion   = 1
	FindingSchemaVersion  = 1
)

type Readiness string

const (
	Ready        Readiness = "READY"
	Blocked      Readiness = "BLOCKED"
	Inconclusive Readiness = "INCONCLUSIVE"
)

type RuleStatus string

const (
	Pass    RuleStatus = "PASS"
	Warn    RuleStatus = "WARN"
	Fail    RuleStatus = "FAIL"
	Unknown RuleStatus = "INCONCLUSIVE"
)

type Role string

const (
	RoleMaster Role = "master"
	RoleNode   Role = "node"
)

type Manifest struct {
	DoctorVersion   string        `json:"doctor_version"`
	RulePackVersion string        `json:"rule_pack_version"`
	Command         string        `json:"command"`
	TargetVersion   string        `json:"target_version,omitempty"`
	StartedAt       time.Time     `json:"started_at"`
	FinishedAt      time.Time     `json:"finished_at"`
	Observe         time.Duration `json:"observe_ns"`
	SampleCap       int           `json:"sample_cap"`
	RedactionKeyID  string        `json:"redaction_key_id"`
}

type Snapshot struct {
	SchemaVersion int             `json:"schema_version"`
	Sensitive     bool            `json:"sensitive"`
	Manifest      Manifest        `json:"manifest"`
	Panels        []PanelSnapshot `json:"panels"`
}

type PanelSnapshot struct {
	ID                  string                    `json:"id"`
	Role                Role                      `json:"role"`
	Alias               string                    `json:"alias"`
	GUIDAlias           string                    `json:"guid_alias"`
	PanelVersion        string                    `json:"panel_version,omitempty"`
	XrayVersion         string                    `json:"xray_version,omitempty"`
	XrayState           string                    `json:"xray_state,omitempty"`
	OpenAPIHash         string                    `json:"openapi_hash,omitempty"`
	GeneratedConfigHash string                    `json:"generated_config_hash,omitempty"`
	Inbounds            []InboundSnapshot         `json:"inbounds"`
	Clients             []ClientSnapshot          `json:"clients"`
	Nodes               []NodeSnapshot            `json:"nodes,omitempty"`
	Subscriptions       []SubscriptionObservation `json:"subscriptions,omitempty"`
	Traffic             []TrafficObservation      `json:"traffic,omitempty"`
	Observations        []Observation             `json:"observations,omitempty"`
}

type InboundSnapshot struct {
	Alias               string   `json:"alias"`
	OriginGUIDAlias     string   `json:"origin_guid_alias"`
	Protocol            string   `json:"protocol"`
	Network             string   `json:"network,omitempty"`
	Security            string   `json:"security,omitempty"`
	Flow                string   `json:"flow,omitempty"`
	Enabled             bool     `json:"enabled"`
	ClientAliases       []string `json:"client_aliases,omitempty"`
	SavedConfigHash     string   `json:"saved_config_hash,omitempty"`
	GeneratedConfigHash string   `json:"generated_config_hash,omitempty"`
	NetworkIdentifiers  []string `json:"network_identifiers,omitempty"`
}

type ClientSnapshot struct {
	Alias             string   `json:"alias"`
	Enabled           bool     `json:"enabled"`
	TotalBytes        int64    `json:"total_bytes,omitempty"`
	UsedBytes         int64    `json:"used_bytes,omitempty"`
	ExpiryUnixMS      int64    `json:"expiry_unix_ms,omitempty"`
	InboundAliases    []string `json:"inbound_aliases,omitempty"`
	SubscriptionAlias string   `json:"subscription_alias,omitempty"`
}

type NodeSnapshot struct {
	Alias          string   `json:"alias"`
	GUIDAlias      string   `json:"guid_alias"`
	Status         string   `json:"status,omitempty"`
	PanelVersion   string   `json:"panel_version,omitempty"`
	XrayVersion    string   `json:"xray_version,omitempty"`
	InboundAliases []string `json:"inbound_aliases,omitempty"`
}

type SubscriptionObservation struct {
	ClientAlias string   `json:"client_alias"`
	Stratum     string   `json:"stratum"`
	Format      string   `json:"format"`
	Parsed      bool     `json:"parsed"`
	SemanticSet []string `json:"semantic_set,omitempty"`
	ShareSet    []string `json:"share_set,omitempty"`
	ErrorCode   string   `json:"error_code,omitempty"`
}

type TrafficObservation struct {
	ClientAlias string    `json:"client_alias"`
	At          time.Time `json:"at"`
	Up          int64     `json:"up"`
	Down        int64     `json:"down"`
	Enabled     bool      `json:"enabled"`
}

type Observation struct {
	RuleID       string `json:"rule_id"`
	Subject      string `json:"subject"`
	Kind         string `json:"kind"`
	Observed     string `json:"observed,omitempty"`
	Expected     string `json:"expected,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Blocking     bool   `json:"blocking,omitempty"`
	Inconclusive bool   `json:"inconclusive,omitempty"`
}

type Finding struct {
	SchemaVersion int        `json:"schema_version"`
	RuleID        string     `json:"rule_id"`
	Status        RuleStatus `json:"status"`
	Title         string     `json:"title"`
	Subject       string     `json:"subject,omitempty"`
	Observed      string     `json:"observed,omitempty"`
	Expected      string     `json:"expected,omitempty"`
	Evidence      string     `json:"evidence,omitempty"`
	Impact        string     `json:"impact,omitempty"`
	Remediation   string     `json:"remediation,omitempty"`
}

type Change struct {
	Panel    string `json:"panel"`
	Field    string `json:"field"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	Severity string `json:"severity"`
}

type Result struct {
	SchemaVersion int       `json:"schema_version"`
	Readiness     Readiness `json:"readiness"`
	Manifest      Manifest  `json:"manifest"`
	PanelCount    int       `json:"panel_count"`
	Findings      []Finding `json:"findings"`
	Changes       []Change  `json:"changes,omitempty"`
	Sensitive     bool      `json:"sensitive"`
}
