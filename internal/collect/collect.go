package collect

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/adapter"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/api"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/config"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/redact"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/subscription"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/version"
)

type Collector struct {
	runtime  *config.Runtime
	redactor *redact.Redactor
	clients  map[string]*api.Client
}

type panelWork struct {
	config    config.Panel
	raw       adapter.ParsedPanel
	safe      model.PanelSnapshot
	supported bool
}

func New(runtime *config.Runtime) (*Collector, error) {
	r := redact.New(runtime.RedactionKey)
	clients := make(map[string]*api.Client, len(runtime.Config.Panels))
	for _, panel := range runtime.Config.Panels {
		client, err := api.New(api.Options{
			BaseURL: panel.URL, Token: runtime.Tokens[panel.ID], Timeout: runtime.RequestTimeout,
			TLSPinSHA256: panel.TLSPinSHA256, ProxyURL: runtime.ProxyURL,
			AllowedRedirectHosts: runtime.Config.Transport.AllowedRedirectHosts,
		})
		if err != nil {
			return nil, fmt.Errorf("panel %s client: %w", panel.ID, err)
		}
		clients[panel.ID] = client
	}
	return &Collector{runtime: runtime, redactor: r, clients: clients}, nil
}

func (c *Collector) Collect(ctx context.Context, command, target string, observe time.Duration) (model.Snapshot, error) {
	started := time.Now().UTC()
	works := make([]panelWork, len(c.runtime.Config.Panels))
	sem := make(chan struct{}, c.runtime.Config.Transport.PanelConcurrency)
	var wg sync.WaitGroup
	for i, panel := range c.runtime.Config.Panels {
		wg.Add(1)
		go func(i int, panel config.Panel) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			works[i] = c.collectPanel(ctx, panel)
		}(i, panel)
	}
	wg.Wait()
	c.reconcileTopology(works, target, command)
	c.collectAllSubscriptions(ctx, works)

	if observe > 0 {
		interval := observe / 5
		if interval <= 0 {
			interval = time.Millisecond
		}
		for sample := 1; sample < 6; sample++ {
			select {
			case <-ctx.Done():
				return model.Snapshot{}, ctx.Err()
			case <-time.After(interval):
			}
			at := time.Now().UTC()
			c.sampleAllTraffic(ctx, works, at)
		}
	}

	panels := make([]model.PanelSnapshot, len(works))
	for i := range works {
		panels[i] = works[i].safe
		sortPanel(&panels[i])
	}
	sort.Slice(panels, func(i, j int) bool { return panels[i].ID < panels[j].ID })
	return model.Snapshot{
		SchemaVersion: model.SnapshotSchemaVersion,
		Sensitive:     c.runtime.Config.Report.IncludeNetworkIdentifiers,
		Manifest:      model.Manifest{DoctorVersion: version.Version, RulePackVersion: version.RulePackVersion, Command: command, TargetVersion: target, StartedAt: started, FinishedAt: time.Now().UTC(), Observe: observe, SampleCap: c.runtime.Config.Subscription.SampleCap, RedactionKeyID: c.runtime.Config.Redaction.KeyID},
		Panels:        panels,
	}, nil
}

func (c *Collector) sampleAllTraffic(ctx context.Context, works []panelWork, at time.Time) {
	sem := make(chan struct{}, c.runtime.Config.Transport.PanelConcurrency)
	var wg sync.WaitGroup
	for i := range works {
		if !works[i].supported {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c.sampleTraffic(ctx, &works[i], at)
		}(i)
	}
	wg.Wait()
}

func (c *Collector) collectPanel(ctx context.Context, panel config.Panel) panelWork {
	work := panelWork{config: panel}
	work.safe = model.PanelSnapshot{ID: panel.ID, Role: panel.Role, Alias: c.redactor.Alias("panel", panel.ExpectedGUID), GUIDAlias: c.redactor.Alias("guid", panel.ExpectedGUID)}
	client := c.clients[panel.ID]

	var openAPIMissing []string
	openapi := c.fetch(ctx, &work, client, "/panel/api/openapi.json", false)
	if openapi != nil {
		work.safe.OpenAPIHash = redact.HashBytes(openapi)
		openAPIMissing = adapter.ValidateOpenAPI(openapi)
	}
	if body := c.fetch(ctx, &work, client, "/panel/api/server/getPanelUpdateInfo", true); body != nil {
		if value, err := adapter.ParseUpdateInfo(body); err == nil {
			work.raw.PanelVersion = value
			work.safe.PanelVersion = value
		} else {
			c.addParseObservation(&work, "API-001", "panel_update_info", err)
		}
	}
	if body := c.fetch(ctx, &work, client, "/panel/api/server/status", true); body != nil {
		if state, value, err := adapter.ParseStatus(body); err == nil {
			work.raw.XrayState, work.raw.XrayVersion = safeStatus(state), value
			work.safe.XrayState, work.safe.XrayVersion = safeStatus(state), value
		} else {
			c.addParseObservation(&work, "API-001", "server_status", err)
		}
	}
	work.supported = work.raw.PanelVersion == "v3.5.0" || work.raw.PanelVersion == "v3.6.0"
	for _, missing := range openAPIMissing {
		observation := model.Observation{RuleID: "API-003", Subject: work.safe.Alias, Kind: "required_openapi_operation_missing", Observed: missing, Expected: "required operation present", Blocking: work.supported, Inconclusive: !work.supported}
		work.safe.Observations = append(work.safe.Observations, observation)
	}
	if !work.supported {
		return work
	}
	if body := c.fetch(ctx, &work, client, "/panel/api/server/getConfigJson", true); body != nil {
		if value, err := adapter.ParseGenerated(body); err == nil {
			work.raw.Generated = value
			canonical, _ := adapter.CanonicalJSON(value)
			work.safe.GeneratedConfigHash = c.redactor.Digest(string(canonical))
		} else {
			c.addParseObservation(&work, "API-001", "generated_config", err)
		}
	}
	if body := c.fetch(ctx, &work, client, "/panel/api/inbounds/list", true); body != nil {
		if value, err := adapter.ParseInbounds(body); err == nil {
			work.raw.Inbounds = value
		} else {
			c.addParseObservation(&work, "API-001", "inbounds", err)
		}
	}
	if body := c.fetch(ctx, &work, client, "/panel/api/clients/list", true); body != nil {
		if value, err := adapter.ParseClients(body); err == nil {
			work.raw.Clients = value
		} else {
			c.addParseObservation(&work, "API-001", "clients", err)
		}
	}
	if body := c.fetchPostRead(ctx, &work, client, "/panel/api/setting/all", true); body != nil {
		if value, err := adapter.ParseSettings(body); err == nil {
			work.raw.Settings = value
		} else {
			c.addParseObservation(&work, "API-001", "settings", err)
		}
	}
	if panel.Role == model.RoleMaster {
		if body := c.fetch(ctx, &work, client, "/panel/api/nodes/list", true); body != nil {
			if value, err := adapter.ParseNodes(body); err == nil {
				work.raw.Nodes = value
			} else {
				c.addParseObservation(&work, "API-001", "nodes", err)
			}
		}
	}

	work.safe.Observations = append(work.safe.Observations, adapter.ConfigObservations(work.raw.Inbounds, work.raw.Generated, c.redactor, panel.ExpectedGUID)...)
	c.normalize(&work)
	return work
}

func (c *Collector) fetch(ctx context.Context, work *panelWork, client *api.Client, path string, expectEnvelope bool) []byte {
	return c.fetchWith(ctx, work, path, expectEnvelope, "GET", client.GetPanel)
}

func (c *Collector) fetchPostRead(ctx context.Context, work *panelWork, client *api.Client, path string, expectEnvelope bool) []byte {
	return c.fetchWith(ctx, work, path, expectEnvelope, "POST", client.PostPanelRead)
}

func (c *Collector) fetchWith(ctx context.Context, work *panelWork, path string, expectEnvelope bool, verb string, request func(context.Context, string) (api.Response, error)) []byte {
	resp, err := request(ctx, path)
	if err != nil {
		work.safe.Observations = append(work.safe.Observations, model.Observation{RuleID: "API-001", Subject: work.safe.Alias, Kind: "request_failed", Observed: redact.SanitizedErrorCode(err.Error()), Expected: "successful authenticated read", Evidence: verb + " " + pathTemplate(path), Inconclusive: true})
		return nil
	}
	if resp.BodyLength == 0 {
		work.safe.Observations = append(work.safe.Observations, model.Observation{RuleID: "API-001", Subject: work.safe.Alias, Kind: "empty_success", Observed: "HTTP 2xx with empty body", Expected: "non-empty JSON response", Evidence: verb + " " + pathTemplate(path), Blocking: true})
		return nil
	}
	if resp.ContentType != "application/json" && !strings.HasSuffix(resp.ContentType, "+json") {
		work.safe.Observations = append(work.safe.Observations, model.Observation{RuleID: "API-001", Subject: work.safe.Alias, Kind: "media_type_mismatch", Observed: safeMediaType(resp.ContentType), Expected: "application/json", Evidence: verb + " " + pathTemplate(path), Blocking: true})
		return nil
	}
	if expectEnvelope {
		if err := adapter.ValidateEnvelope(resp.Body); err != nil {
			work.safe.Observations = append(work.safe.Observations, model.Observation{RuleID: "API-001", Subject: work.safe.Alias, Kind: "envelope_mismatch", Observed: redact.SanitizedErrorCode(err.Error()), Expected: "successful API envelope", Evidence: verb + " " + pathTemplate(path), Blocking: true})
			return nil
		}
	}
	return resp.Body
}

func (c *Collector) normalize(work *panelWork) {
	guid := work.config.ExpectedGUID
	inboundAlias := map[string]string{}
	for _, in := range work.raw.Inbounds {
		alias := c.redactor.Alias("inbound", adapter.InboundIdentity(in, guid))
		originGUID := in.OriginNodeGUID
		if originGUID == "" {
			originGUID = guid
		}
		inboundAlias[in.ID] = alias
		canonical, _ := adapter.CanonicalJSON(adapter.InboundConnectionState(in))
		clients := make([]string, 0, len(in.ClientIDs))
		for _, id := range in.ClientIDs {
			clients = append(clients, c.redactor.Alias("client", id))
		}
		networkIdentifiers := []string(nil)
		if c.runtime.Config.Report.IncludeNetworkIdentifiers {
			networkIdentifiers = append(networkIdentifiers, in.NetworkIdentifiers...)
		}
		work.safe.Inbounds = append(work.safe.Inbounds, model.InboundSnapshot{Alias: alias, OriginGUIDAlias: c.redactor.Alias("guid", originGUID), Protocol: in.Protocol, Network: in.Network, Security: in.Security, Flow: in.Flow, Enabled: in.Enabled, ClientAliases: clients, SavedConfigHash: c.redactor.Digest(string(canonical)), NetworkIdentifiers: networkIdentifiers})
	}
	for _, client := range work.raw.Clients {
		alias := c.redactor.Alias("client", client.Email)
		var inbounds []string
		for _, id := range client.InboundIDs {
			if value := inboundAlias[id]; value != "" {
				inbounds = append(inbounds, value)
			}
		}
		work.safe.Clients = append(work.safe.Clients, model.ClientSnapshot{Alias: alias, Enabled: client.Enabled, TotalBytes: client.Total, UsedBytes: client.Up + client.Down, ExpiryUnixMS: client.Expiry, InboundAliases: inbounds, SubscriptionAlias: c.redactor.Alias("subscription", client.SubID)})
		work.safe.Traffic = append(work.safe.Traffic, model.TrafficObservation{ClientAlias: alias, At: time.Now().UTC(), Up: client.Up, Down: client.Down, Enabled: client.Enabled})
	}
	for _, node := range work.raw.Nodes {
		var inbounds []string
		for _, id := range node.InboundIDs {
			if value := inboundAlias[id]; value != "" {
				inbounds = append(inbounds, value)
			}
		}
		work.safe.Nodes = append(work.safe.Nodes, model.NodeSnapshot{Alias: c.redactor.Alias("node", node.GUID), GUIDAlias: c.redactor.Alias("guid", node.GUID), Status: safeStatus(node.Status), PanelVersion: node.PanelVersion, XrayVersion: node.XrayVersion, InboundAliases: inbounds})
	}
}

func (c *Collector) collectAllSubscriptions(ctx context.Context, works []panelWork) {
	type allocation struct {
		index, eligible, budget int
	}
	allocations := make([]allocation, 0, len(works))
	for i := range works {
		if works[i].supported {
			allocations = append(allocations, allocation{index: i, eligible: eligibleSubscriptionCandidates(&works[i])})
		}
	}
	sort.Slice(allocations, func(i, j int) bool {
		return works[allocations[i].index].config.ID < works[allocations[j].index].config.ID
	})
	remaining := c.runtime.Config.Subscription.SampleCap
	for remaining > 0 {
		assigned := false
		for i := range allocations {
			if remaining == 0 {
				break
			}
			if allocations[i].budget < allocations[i].eligible {
				allocations[i].budget++
				remaining--
				assigned = true
			}
		}
		if !assigned {
			break
		}
	}
	sem := make(chan struct{}, c.runtime.Config.Transport.PanelConcurrency)
	var wg sync.WaitGroup
	for _, alloc := range allocations {
		if alloc.budget == 0 {
			continue
		}
		wg.Add(1)
		go func(alloc allocation) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c.collectSubscriptions(ctx, &works[alloc.index], alloc.budget)
		}(alloc)
	}
	wg.Wait()
}

func eligibleSubscriptionCandidates(work *panelWork) int {
	inbounds := map[string]bool{}
	for _, inbound := range work.raw.Inbounds {
		inbounds[inbound.ID] = true
	}
	count := 0
	for _, client := range work.raw.Clients {
		if !client.Enabled || client.SubID == "" || client.Email == "" {
			continue
		}
		for _, id := range client.InboundIDs {
			if inbounds[id] {
				count++
			}
		}
	}
	return count
}

func (c *Collector) collectSubscriptions(ctx context.Context, work *panelWork, sampleCap int) {
	type candidate struct {
		client  adapter.RawClient
		stratum string
		rank    string
	}
	inbounds := map[string]adapter.RawInbound{}
	for _, inbound := range work.raw.Inbounds {
		inbounds[inbound.ID] = inbound
	}
	var candidates []candidate
	for _, client := range work.raw.Clients {
		if !client.Enabled || client.SubID == "" || client.Email == "" {
			continue
		}
		for _, id := range client.InboundIDs {
			in := inbounds[id]
			if in.ID == "" {
				continue
			}
			stratum := strings.Join([]string{in.Protocol, in.Network, in.Security, c.redactor.Alias("inbound", adapter.InboundIdentity(in, work.config.ExpectedGUID))}, "/")
			candidates = append(candidates, candidate{client: client, stratum: stratum, rank: c.redactor.Digest(stratum + "\x00" + client.SubID)})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].stratum == candidates[j].stratum {
			return candidates[i].rank < candidates[j].rank
		}
		return candidates[i].stratum < candidates[j].stratum
	})
	selected := make([]candidate, 0, sampleCap)
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if len(selected) >= sampleCap {
			break
		}
		if !seen[candidate.stratum] {
			selected = append(selected, candidate)
			seen[candidate.stratum] = true
		}
	}
	for _, candidate := range candidates {
		if len(selected) >= sampleCap {
			break
		}
		already := false
		for _, chosen := range selected {
			if chosen.rank == candidate.rank {
				already = true
				break
			}
		}
		if !already {
			selected = append(selected, candidate)
		}
	}

	for _, sample := range selected {
		clientAlias := c.redactor.Alias("client", sample.client.Email)
		shareBody := c.fetch(ctx, work, c.clients[work.config.ID], "/panel/api/clients/links/"+url.PathEscape(sample.client.Email), true)
		subBody := c.fetch(ctx, work, c.clients[work.config.ID], "/panel/api/clients/subLinks/"+url.PathEscape(sample.client.SubID), true)
		observation := model.SubscriptionObservation{ClientAlias: clientAlias, Stratum: sample.stratum, Format: "raw"}
		if shareBody == nil || subBody == nil {
			observation.ErrorCode = "api_evidence_missing"
			work.safe.Subscriptions = append(work.safe.Subscriptions, observation)
			continue
		}
		shareObj, shareErr := adapter.DecodeEnvelope(shareBody)
		subObj, subErr := adapter.DecodeEnvelope(subBody)
		if shareErr == nil {
			observation.ShareSet, shareErr = subscription.ParseLinkArray(shareObj, c.redactor)
		}
		if subErr == nil {
			observation.SemanticSet, subErr = subscription.ParseLinkArray(subObj, c.redactor)
		}
		observation.Parsed = shareErr == nil && subErr == nil
		if !observation.Parsed {
			observation.ErrorCode = "parse_error"
		}
		work.safe.Subscriptions = append(work.safe.Subscriptions, observation)
	}
	// External raw/JSON/Clash checks are attempted only when their origins are
	// explicit in panel settings and allowlisted. This prevents Doctor from
	// turning panel-controlled values into unrestricted network access.
	for _, format := range []struct{ name, uri, path, enabled string }{
		{"raw", "subURI", "subPath", "subEnable"},
		{"json", "subJsonURI", "subJsonPath", "subJsonEnable"},
		{"clash", "subClashURI", "subClashPath", "subClashEnable"},
	} {
		if !settingBool(work.raw.Settings[format.enabled], format.name == "raw") {
			continue
		}
		base := settingString(work.raw.Settings[format.uri])
		if base == "" || len(selected) == 0 {
			continue
		}
		for _, sample := range selected {
			rawURL, err := buildSubscriptionURL(base, settingString(work.raw.Settings[format.path]), sample.client.SubID)
			obs := model.SubscriptionObservation{ClientAlias: c.redactor.Alias("client", sample.client.Email), Stratum: sample.stratum, Format: format.name}
			if err != nil {
				obs.ErrorCode = "invalid_subscription_origin"
				work.safe.Subscriptions = append(work.safe.Subscriptions, obs)
				continue
			}
			resp, err := c.clients[work.config.ID].GetExternal(ctx, rawURL)
			if err != nil {
				obs.ErrorCode = redact.SanitizedErrorCode(err.Error())
				work.safe.Subscriptions = append(work.safe.Subscriptions, obs)
				continue
			}
			obs.SemanticSet, err = subscription.Parse(format.name, resp.Body, c.redactor)
			obs.Parsed = err == nil
			if err != nil {
				obs.ErrorCode = "parse_error"
			}
			work.safe.Subscriptions = append(work.safe.Subscriptions, obs)
		}
	}
}

func (c *Collector) sampleTraffic(ctx context.Context, work *panelWork, at time.Time) {
	resp, err := c.clients[work.config.ID].GetPanel(ctx, "/panel/api/clients/list")
	if err != nil {
		work.safe.Observations = append(work.safe.Observations, model.Observation{RuleID: "API-001", Subject: work.safe.Alias, Kind: "traffic_sample_failed", Observed: redact.SanitizedErrorCode(err.Error()), Expected: "traffic sample", Inconclusive: true})
		return
	}
	clients, err := adapter.ParseClients(resp.Body)
	if err != nil {
		work.safe.Observations = append(work.safe.Observations, model.Observation{RuleID: "API-001", Subject: work.safe.Alias, Kind: "traffic_sample_parse_failed", Observed: "parse_error", Expected: "traffic sample", Inconclusive: true})
		return
	}
	for _, client := range clients {
		work.safe.Traffic = append(work.safe.Traffic, model.TrafficObservation{ClientAlias: c.redactor.Alias("client", client.Email), At: at, Up: client.Up, Down: client.Down, Enabled: client.Enabled})
	}
}

func (c *Collector) reconcileTopology(works []panelWork, target, command string) {
	var master *panelWork
	configuredByMasterGUID := map[string]*panelWork{}
	for i := range works {
		if works[i].config.Role == model.RoleMaster {
			master = &works[i]
		} else {
			configuredByMasterGUID[works[i].config.MasterNodeGUID] = &works[i]
		}
	}
	if master == nil {
		return
	}
	if !master.supported {
		for _, child := range configuredByMasterGUID {
			master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-001", Subject: child.safe.Alias, Kind: "topology_evidence_unavailable", Observed: "master version is unsupported or unknown", Expected: "supported master topology", Inconclusive: true})
		}
		return
	}
	discovered := map[string]adapter.RawNode{}
	for _, node := range master.raw.Nodes {
		discovered[node.GUID] = node
		child := configuredByMasterGUID[node.GUID]
		if child == nil {
			master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-001", Subject: c.redactor.Alias("node", node.GUID), Kind: "node_credentials_missing", Observed: "master reports a node without Doctor credentials", Expected: "explicit node configuration", Inconclusive: true})
			continue
		}
		if !strings.EqualFold(node.Status, "online") {
			master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-001", Subject: c.redactor.Alias("node", node.GUID), Kind: "node_offline", Observed: safeStatus(node.Status), Expected: "online", Inconclusive: true})
		}
		if child.config.ExpectedGUID != node.GUID {
			master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-001", Subject: child.safe.Alias, Kind: "node_identity_mismatch", Observed: child.safe.GUIDAlias, Expected: c.redactor.Alias("guid", node.GUID), Blocking: true})
		}
		if child.safe.XrayVersion != "" && master.safe.XrayVersion != "" && child.safe.XrayVersion != master.safe.XrayVersion {
			master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-001", Subject: child.safe.Alias, Kind: "xray_version_skew", Observed: child.safe.XrayVersion, Expected: master.safe.XrayVersion, Evidence: "direct panel comparison"})
		}
		if node.PanelVersion != "" && child.safe.PanelVersion != "" && node.PanelVersion != child.safe.PanelVersion {
			master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-001", Subject: child.safe.Alias, Kind: "reported_panel_version_skew", Observed: node.PanelVersion, Expected: child.safe.PanelVersion, Evidence: "master heartbeat versus direct read"})
		}
		if node.XrayVersion != "" && child.safe.XrayVersion != "" && node.XrayVersion != child.safe.XrayVersion {
			master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-001", Subject: child.safe.Alias, Kind: "reported_xray_version_skew", Observed: node.XrayVersion, Expected: child.safe.XrayVersion, Evidence: "master heartbeat versus direct read"})
		}
	}
	for guid, child := range configuredByMasterGUID {
		if discovered[guid].GUID == "" {
			master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-003", Subject: child.safe.Alias, Kind: "configured_node_missing_from_master", Observed: "configured node absent", Expected: "node listed by master", Blocking: true})
		}
	}
	if command == "verify" && target != "" {
		for i := range works {
			if works[i].safe.PanelVersion == "" {
				works[i].safe.Observations = append(works[i].safe.Observations, model.Observation{RuleID: "NODE-001", Subject: works[i].safe.Alias, Kind: "panel_version_unknown", Observed: "unknown", Expected: target, Inconclusive: true})
			} else if works[i].safe.PanelVersion != target {
				works[i].safe.Observations = append(works[i].safe.Observations, model.Observation{RuleID: "NODE-001", Subject: works[i].safe.Alias, Kind: "target_version_mismatch", Observed: works[i].safe.PanelVersion, Expected: target, Blocking: true})
			}
		}
	}
	for guid, child := range configuredByMasterGUID {
		if !child.supported {
			master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-003", Subject: child.safe.Alias, Kind: "node_object_evidence_unavailable", Observed: "node version is unsupported or unknown", Expected: "supported node object snapshot", Inconclusive: true})
			continue
		}
		expected, actual := map[string]bool{}, map[string]bool{}
		expectedClients, actualClients := map[string]bool{}, map[string]bool{}
		for _, in := range master.raw.Inbounds {
			if in.OriginNodeGUID == guid {
				expected[c.redactor.Alias("inbound", adapter.InboundIdentity(in, master.config.ExpectedGUID))] = true
				for _, clientID := range in.ClientIDs {
					expectedClients[c.redactor.Alias("client", clientID)] = true
				}
			}
		}
		for _, in := range child.raw.Inbounds {
			actual[c.redactor.Alias("inbound", adapter.InboundIdentity(in, child.config.ExpectedGUID))] = true
		}
		for _, client := range child.raw.Clients {
			actualClients[c.redactor.Alias("client", client.Email)] = true
		}
		for alias := range expected {
			if !actual[alias] {
				master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-003", Subject: alias, Kind: "assigned_inbound_missing", Observed: "missing on node", Expected: "assigned inbound present", Blocking: true})
			}
		}
		for alias := range expectedClients {
			if !actualClients[alias] {
				master.safe.Observations = append(master.safe.Observations, model.Observation{RuleID: "NODE-003", Subject: alias, Kind: "assigned_client_missing", Observed: "missing on node", Expected: "assigned client present", Blocking: true})
			}
		}
	}
}

func (c *Collector) addParseObservation(work *panelWork, ruleID, kind string, err error) {
	observation := model.Observation{RuleID: ruleID, Subject: work.safe.Alias, Kind: kind, Observed: redact.SanitizedErrorCode(err.Error()), Expected: "valid documented response", Blocking: true}
	if strings.Contains(strings.ToLower(err.Error()), "api reported failure") {
		observation.Blocking = false
		observation.Inconclusive = true
	}
	work.safe.Observations = append(work.safe.Observations, observation)
}

func buildSubscriptionURL(base, path, subID string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("invalid subscription base")
	}
	if path == "" {
		path = u.Path
	}
	u.Path = strings.TrimRight(path, "/") + "/" + url.PathEscape(subID)
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

func settingString(v any) string {
	s, _ := v.(string)
	return s
}

func settingBool(v any, fallback bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	if s, ok := v.(string); ok {
		return strings.EqualFold(s, "true")
	}
	return fallback
}

func pathTemplate(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if i > 0 && (parts[i-1] == "links" || parts[i-1] == "subLinks") && part != "" {
			parts[i] = "{redacted}"
		}
	}
	return strings.Join(parts, "/")
}

func safeMediaType(value string) string {
	if value == "" {
		return "missing"
	}
	if len(value) > 64 {
		return "invalid"
	}
	return value
}

func safeStatus(value string) string {
	switch strings.ToLower(value) {
	case "online", "offline", "running", "stopped", "error", "unknown":
		return strings.ToLower(value)
	default:
		return "unknown"
	}
}

func sortPanel(panel *model.PanelSnapshot) {
	sort.Slice(panel.Inbounds, func(i, j int) bool { return panel.Inbounds[i].Alias < panel.Inbounds[j].Alias })
	sort.Slice(panel.Clients, func(i, j int) bool { return panel.Clients[i].Alias < panel.Clients[j].Alias })
	sort.Slice(panel.Nodes, func(i, j int) bool { return panel.Nodes[i].Alias < panel.Nodes[j].Alias })
	sort.Slice(panel.Subscriptions, func(i, j int) bool {
		if panel.Subscriptions[i].ClientAlias == panel.Subscriptions[j].ClientAlias {
			return panel.Subscriptions[i].Format < panel.Subscriptions[j].Format
		}
		return panel.Subscriptions[i].ClientAlias < panel.Subscriptions[j].ClientAlias
	})
	sort.Slice(panel.Traffic, func(i, j int) bool {
		if panel.Traffic[i].At.Equal(panel.Traffic[j].At) {
			return panel.Traffic[i].ClientAlias < panel.Traffic[j].ClientAlias
		}
		return panel.Traffic[i].At.Before(panel.Traffic[j].At)
	})
}
