package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/redact"
)

var RequiredOpenAPIPaths = map[string][]string{
	"/panel/api/openapi.json":              {"get"},
	"/panel/api/server/status":             {"get"},
	"/panel/api/server/getPanelUpdateInfo": {"get"},
	"/panel/api/server/getConfigJson":      {"get"},
	"/panel/api/inbounds/list":             {"get"},
	"/panel/api/clients/list":              {"get"},
	"/panel/api/clients/subLinks/{subId}":  {"get"},
	"/panel/api/clients/links/{email}":     {"get"},
	"/panel/api/nodes/list":                {"get"},
	"/panel/api/setting/all":               {"get"},
}

type Envelope struct {
	Success bool            `json:"success"`
	Message string          `json:"msg"`
	Object  json.RawMessage `json:"obj"`
}

type ParsedPanel struct {
	PanelVersion string
	XrayVersion  string
	XrayState    string
	Inbounds     []RawInbound
	Clients      []RawClient
	Nodes        []RawNode
	Settings     map[string]any
	Generated    map[string]any
	Observations []model.Observation
}

type RawInbound struct {
	ID                 string
	Tag                string
	Listen             string
	Port               int64
	Protocol           string
	Network            string
	Security           string
	Flow               string
	OriginNodeGUID     string
	Enabled            bool
	ClientIDs          []string
	Saved              map[string]any
	Fallbacks          []map[string]any
	NetworkIdentifiers []string
}

type RawClient struct {
	ID         string
	Email      string
	SubID      string
	Enabled    bool
	Total      int64
	Up         int64
	Down       int64
	Expiry     int64
	InboundIDs []string
}

type RawNode struct {
	GUID         string
	Name         string
	Status       string
	PanelVersion string
	XrayVersion  string
	InboundIDs   []string
}

func DecodeEnvelope(body []byte) (json.RawMessage, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("empty response body")
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("invalid JSON envelope")
	}
	if !env.Success {
		return nil, fmt.Errorf("API reported failure")
	}
	if len(bytes.TrimSpace(env.Object)) == 0 || bytes.Equal(bytes.TrimSpace(env.Object), []byte("null")) {
		return nil, fmt.Errorf("successful API response contains no object")
	}
	return env.Object, nil
}

func ValidateEnvelope(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("empty response body")
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(body, &value); err != nil {
		return fmt.Errorf("invalid JSON envelope")
	}
	rawSuccess, ok := value["success"]
	if !ok {
		return fmt.Errorf("response envelope is missing success")
	}
	var success bool
	if err := json.Unmarshal(rawSuccess, &success); err != nil {
		return fmt.Errorf("response envelope success is not boolean")
	}
	return nil
}

func ValidateOpenAPI(body []byte) []string {
	var doc struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.OpenAPI == "" {
		return []string{"document is not a valid OpenAPI object"}
	}
	var missing []string
	for path, methods := range RequiredOpenAPIPaths {
		ops, ok := doc.Paths[path]
		if !ok {
			missing = append(missing, path)
			continue
		}
		for _, method := range methods {
			rawOperation, ok := ops[method]
			if !ok {
				missing = append(missing, strings.ToUpper(method)+" "+path)
				continue
			}
			if !hasJSONSuccessResponse(rawOperation) {
				missing = append(missing, strings.ToUpper(method)+" "+path+" compatible JSON success response")
			}
		}
	}
	sort.Strings(missing)
	return missing
}

func hasJSONSuccessResponse(raw json.RawMessage) bool {
	var operation struct {
		Responses map[string]struct {
			Content map[string]json.RawMessage `json:"content"`
		} `json:"responses"`
	}
	if json.Unmarshal(raw, &operation) != nil {
		return false
	}
	for status, response := range operation.Responses {
		if strings.HasPrefix(status, "2") {
			if _, ok := response.Content["application/json"]; ok {
				return true
			}
			for contentType := range response.Content {
				if strings.HasSuffix(strings.ToLower(contentType), "+json") {
					return true
				}
			}
		}
	}
	return false
}

func ParseUpdateInfo(body []byte) (string, error) {
	obj, err := DecodeEnvelope(body)
	if err != nil {
		return "", err
	}
	var info struct {
		CurrentVersion string `json:"currentVersion"`
	}
	if err := json.Unmarshal(obj, &info); err != nil || info.CurrentVersion == "" {
		return "", fmt.Errorf("panel version missing")
	}
	version := normalizeVersion(info.CurrentVersion)
	if version == "" {
		return "", fmt.Errorf("panel version is invalid")
	}
	return version, nil
}

func ParseStatus(body []byte) (state, version string, err error) {
	obj, err := DecodeEnvelope(body)
	if err != nil {
		return "", "", err
	}
	var status struct {
		Xray struct {
			State   string `json:"state"`
			Version string `json:"version"`
		} `json:"xray"`
	}
	if err := json.Unmarshal(obj, &status); err != nil {
		return "", "", fmt.Errorf("invalid status object")
	}
	return status.Xray.State, normalizeVersion(status.Xray.Version), nil
}

func ParseGenerated(body []byte) (map[string]any, error) {
	obj, err := DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(obj, &result); err != nil {
		return nil, fmt.Errorf("invalid generated config")
	}
	return result, nil
}

func ParseSettings(body []byte) (map[string]any, error) {
	obj, err := DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(obj, &result); err != nil {
		return nil, fmt.Errorf("invalid settings object")
	}
	return result, nil
}

func ParseInbounds(body []byte) ([]RawInbound, error) {
	obj, err := DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(obj, &rows); err != nil {
		return nil, fmt.Errorf("invalid inbounds array")
	}
	result := make([]RawInbound, 0, len(rows))
	for _, row := range rows {
		settings := object(row["settings"])
		stream := object(row["streamSettings"])
		network := safeConfigToken(stringValue(stream["network"]))
		if network == "" {
			network = safeConfigToken(stringValue(stream["type"]))
		}
		if network == "" {
			network = "tcp"
		}
		security := safeConfigToken(stringValue(stream["security"]))
		if security == "" {
			security = "none"
		}
		in := RawInbound{
			ID:             scalarString(row["id"]),
			Tag:            stringValue(row["tag"]),
			Listen:         stringValue(row["listen"]),
			Port:           int64Value(row["port"]),
			Protocol:       safeConfigToken(stringValue(row["protocol"])),
			Network:        strings.ToLower(network),
			Security:       security,
			OriginNodeGUID: stringValue(row["originNodeGuid"]),
			Enabled:        boolValue(row["enable"], true),
			Saved:          row,
		}
		in.NetworkIdentifiers = extractNetworkIdentifiers(row, stream)
		for _, raw := range array(settings["clients"]) {
			client := object(raw)
			id := firstNonEmpty(stringValue(client["email"]), stringValue(client["id"]), stringValue(client["password"]), stringValue(client["auth"]))
			if id != "" {
				in.ClientIDs = append(in.ClientIDs, id)
			}
			if in.Flow == "" {
				in.Flow = safeConfigToken(stringValue(client["flow"]))
			}
		}
		for _, raw := range array(settings["fallbacks"]) {
			in.Fallbacks = append(in.Fallbacks, object(raw))
		}
		result = append(result, in)
	}
	return result, nil
}

// extractNetworkIdentifiers deliberately reads a small allowlist of address
// fields. It must never walk arbitrary configuration values because those can
// contain private keys and client credentials.
func extractNetworkIdentifiers(row, stream map[string]any) []string {
	seen := map[string]bool{}
	var result []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if safeNetworkIdentifier(value) && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	add(stringValue(row["listen"]))
	for _, key := range []string{"wsSettings", "httpSettings", "splithttpSettings", "xhttpSettings"} {
		settings := object(stream[key])
		add(stringValue(settings["host"]))
		for _, host := range array(settings["host"]) {
			add(stringValue(host))
		}
		add(stringValue(object(settings["headers"])["Host"]))
	}
	grpc := object(stream["grpcSettings"])
	add(stringValue(grpc["authority"]))
	for _, key := range []string{"tlsSettings", "realitySettings"} {
		security := object(stream[key])
		add(firstNonEmpty(stringValue(security["serverName"]), stringValue(security["target"]), stringValue(security["dest"])))
		for _, name := range array(security["serverNames"]) {
			add(stringValue(name))
		}
	}
	sort.Strings(result)
	return result
}

func safeNetworkIdentifier(value string) bool {
	if value == "" || len(value) > 320 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && !strings.ContainsRune(".-_:[]", char) {
			return false
		}
	}
	return true
}

func ParseClients(body []byte) ([]RawClient, error) {
	obj, err := DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(obj, &rows); err != nil {
		return nil, fmt.Errorf("invalid clients array")
	}
	result := make([]RawClient, 0, len(rows))
	for _, row := range rows {
		traffic := object(row["traffic"])
		client := RawClient{
			ID:      scalarString(row["id"]),
			Email:   stringValue(row["email"]),
			SubID:   firstNonEmpty(stringValue(row["subId"]), stringValue(row["subID"])),
			Enabled: boolValue(row["enable"], true),
			Total:   int64Value(firstValue(row, "totalGB", "total")),
			Up:      int64Value(traffic["up"]),
			Down:    int64Value(traffic["down"]),
			Expiry:  int64Value(row["expiryTime"]),
		}
		if _, ok := row["traffic"]; ok {
			client.Enabled = boolValue(traffic["enable"], client.Enabled)
		}
		for _, id := range array(row["inboundIds"]) {
			client.InboundIDs = append(client.InboundIDs, scalarString(id))
		}
		result = append(result, client)
	}
	return result, nil
}

func ParseNodes(body []byte) ([]RawNode, error) {
	obj, err := DecodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(obj, &rows); err != nil {
		return nil, fmt.Errorf("invalid nodes array")
	}
	result := make([]RawNode, 0, len(rows))
	for _, row := range rows {
		last := object(firstValue(row, "lastStatus", "statusPatch", "heartbeat"))
		n := RawNode{
			GUID:         firstNonEmpty(stringValue(row["guid"]), stringValue(last["guid"])),
			Name:         stringValue(row["name"]),
			Status:       firstNonEmpty(stringValue(row["status"]), stringValue(last["status"])),
			PanelVersion: normalizeVersion(firstNonEmpty(stringValue(row["panelVersion"]), stringValue(last["panelVersion"]))),
			XrayVersion:  normalizeVersion(firstNonEmpty(stringValue(row["xrayVersion"]), stringValue(last["xrayVersion"]))),
		}
		for _, id := range array(firstValue(row, "inboundIds", "inbounds")) {
			n.InboundIDs = append(n.InboundIDs, scalarString(id))
		}
		result = append(result, n)
	}
	return result, nil
}

func ConfigObservations(inbounds []RawInbound, generated map[string]any, r *redact.Redactor, panelGUID string) []model.Observation {
	var observations []model.Observation
	byID := map[string]RawInbound{}
	for _, in := range inbounds {
		byID[in.ID] = in
	}
	for _, in := range inbounds {
		if in.Protocol == "" {
			observations = append(observations, model.Observation{RuleID: "CFG-002", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "missing_protocol", Observed: "protocol is absent", Expected: "explicit inbound protocol", Blocking: true})
		} else if !knownProtocol(in.Protocol) {
			observations = append(observations, model.Observation{RuleID: "CFG-002", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "unknown_protocol", Observed: in.Protocol, Expected: "v3.5/v3.6 known protocol", Inconclusive: true})
		}
		if !knownNetwork(in.Network) {
			observations = append(observations, model.Observation{RuleID: "CFG-002", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "unknown_transport", Observed: in.Network, Expected: "v3.5/v3.6 known transport", Inconclusive: true})
		}
		if !knownSecurity(in.Security) {
			observations = append(observations, model.Observation{RuleID: "CFG-002", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "unknown_security", Observed: in.Security, Expected: "none, tls, or reality", Inconclusive: true})
		}
		for _, fallback := range in.Fallbacks {
			if stringValue(fallback["dest"]) == "" {
				childID := scalarString(firstValue(fallback, "childId", "childID", "inboundId"))
				child := byID[childID]
				if childID == "" || child.ID == "" || child.Port < 1 || child.Port > 65535 {
					observations = append(observations, model.Observation{RuleID: "CFG-001", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "unresolved_fallback", Observed: "empty destination without resolvable child inbound", Expected: "explicit destination or valid child inbound", Blocking: true})
				}
			}
		}
		stream := object(in.Saved["streamSettings"])
		if in.Security == "reality" {
			reality := object(stream["realitySettings"])
			if reality == nil || firstNonEmpty(stringValue(reality["target"]), stringValue(reality["dest"])) == "" {
				observations = append(observations, model.Observation{RuleID: "CFG-002", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "incomplete_reality", Observed: "REALITY target is absent", Expected: "non-empty REALITY target", Blocking: true})
			}
		}
		if in.Security == "tls" && object(stream["tlsSettings"]) == nil {
			observations = append(observations, model.Observation{RuleID: "CFG-002", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "incomplete_tls", Observed: "TLS settings are absent", Expected: "TLS settings object", Blocking: true})
		}
		if in.Flow != "" && in.Protocol != "vless" {
			observations = append(observations, model.Observation{RuleID: "CFG-002", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "invalid_flow", Observed: "flow is configured for a non-VLESS inbound", Expected: "flow only on VLESS", Blocking: true})
		}
	}

	generatedByTag := map[string]map[string]any{}
	for _, raw := range array(generated["inbounds"]) {
		g := object(raw)
		generatedByTag[stringValue(g["tag"])] = g
	}
	for _, in := range inbounds {
		g := generatedByTag[in.Tag]
		if in.Tag == "" || g == nil {
			observations = append(observations, model.Observation{RuleID: "CFG-003", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "missing_generated_inbound", Observed: "saved inbound has no generated counterpart", Expected: "generated inbound with matching tag", Blocking: true})
			continue
		}
		gStream := object(g["streamSettings"])
		generatedNetwork := strings.ToLower(stringValue(gStream["network"]))
		if generatedNetwork == "" {
			generatedNetwork = "tcp"
		}
		generatedSecurity := strings.ToLower(stringValue(gStream["security"]))
		if generatedSecurity == "" {
			generatedSecurity = "none"
		}
		if strings.ToLower(stringValue(g["protocol"])) != in.Protocol || generatedNetwork != in.Network || generatedSecurity != in.Security {
			observations = append(observations, model.Observation{RuleID: "CFG-003", Subject: inboundAlias(r, panelGUID, in.ID), Kind: "generated_transport_drift", Observed: "generated protocol/transport/security differs from saved state", Expected: "connection-relevant fields match", Blocking: true})
		}
	}
	return observations
}

func knownProtocol(value string) bool {
	switch value {
	case "vmess", "vless", "trojan", "shadowsocks", "wireguard", "hysteria", "hysteria2", "socks", "http", "mixed", "dokodemo-door", "tunnel", "tun", "mtproto":
		return true
	default:
		return false
	}
}

func knownNetwork(value string) bool {
	switch value {
	case "tcp", "raw", "ws", "grpc", "http", "h2", "xhttp", "splithttp", "kcp", "quic", "httpupgrade":
		return true
	default:
		return false
	}
}

func knownSecurity(value string) bool {
	return value == "none" || value == "tls" || value == "reality"
}

func safeConfigToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 64 {
		return ""
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && !strings.ContainsRune("._+-", char) {
			return "unknown"
		}
	}
	return value
}

func InboundIdentity(in RawInbound, panelGUID string) string {
	origin := in.OriginNodeGUID
	if origin == "" {
		origin = panelGUID
	}
	key := in.Tag
	if key == "" {
		key = in.ID
	}
	return origin + "\x00" + key
}

func CanonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func InboundConnectionState(in RawInbound) map[string]any {
	state := map[string]any{
		"enable":         in.Enabled,
		"protocol":       in.Protocol,
		"tag":            in.Tag,
		"originNodeGuid": in.OriginNodeGUID,
	}
	for _, key := range []string{"listen", "port"} {
		if value, ok := in.Saved[key]; ok {
			state[key] = value
		}
	}
	for _, key := range []string{"settings", "streamSettings", "sniffing"} {
		value := in.Saved[key]
		if parsed := object(value); parsed != nil {
			state[key] = parsed
		} else if value != nil {
			state[key] = value
		}
	}
	return state
}

func inboundAlias(r *redact.Redactor, guid, id string) string {
	return r.Alias("inbound", guid+"\x00"+id)
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 64 {
		return ""
	}
	for _, char := range v {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && !strings.ContainsRune(".+_-", char) {
			return ""
		}
	}
	if strings.HasPrefix(v, "dev+") {
		return v
	}
	if !strings.HasPrefix(strings.ToLower(v), "v") {
		return "v" + v
	}
	return "v" + strings.TrimPrefix(strings.ToLower(v), "v")
}

func object(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	if s, ok := v.(string); ok && strings.HasPrefix(strings.TrimSpace(s), "{") {
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil {
			return m
		}
	}
	return nil
}

func array(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func scalarString(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case float64:
		return strconv.FormatInt(int64(n), 10)
	case json.Number:
		return n.String()
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	default:
		return ""
	}
}

func int64Value(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case int:
		return int64(n)
	case int64:
		return n
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	default:
		return 0
	}
}

func boolValue(v any, fallback bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return fallback
}

func firstValue(m map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := m[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
