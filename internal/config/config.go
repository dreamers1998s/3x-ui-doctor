package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
	"gopkg.in/yaml.v3"
)

type Config struct {
	SchemaVersion int          `yaml:"schema_version"`
	Panels        []Panel      `yaml:"panels"`
	Redaction     Redaction    `yaml:"redaction"`
	Subscription  Subscription `yaml:"subscription"`
	Traffic       Traffic      `yaml:"traffic"`
	Transport     Transport    `yaml:"transport"`
	Report        Report       `yaml:"report"`
}

type Panel struct {
	ID             string     `yaml:"id"`
	Role           model.Role `yaml:"role"`
	URL            string     `yaml:"url"`
	TokenEnv       string     `yaml:"token_env"`
	ExpectedGUID   string     `yaml:"expected_guid"`
	MasterNodeGUID string     `yaml:"master_node_guid,omitempty"`
	TLSPinSHA256   string     `yaml:"tls_pin_sha256,omitempty"`
}

type Redaction struct {
	KeyEnv string `yaml:"key_env"`
	KeyID  string `yaml:"key_id"`
}

type Subscription struct {
	SampleCap int `yaml:"sample_cap"`
}

type Traffic struct {
	RelativeThreshold      float64 `yaml:"relative_threshold"`
	AbsoluteThresholdBytes int64   `yaml:"absolute_threshold_bytes"`
	LimitGrace             string  `yaml:"limit_grace"`
}

type Transport struct {
	RequestTimeout       string   `yaml:"request_timeout"`
	PanelConcurrency     int      `yaml:"panel_concurrency"`
	RequestsPerPanel     int      `yaml:"requests_per_panel"`
	ProxyURLEnv          string   `yaml:"proxy_url_env,omitempty"`
	AllowedRedirectHosts []string `yaml:"allowed_redirect_hosts,omitempty"`
}

type Report struct {
	IncludeNetworkIdentifiers bool `yaml:"include_network_identifiers"`
}

type Runtime struct {
	Config         Config
	Tokens         map[string]string
	RedactionKey   []byte
	ProxyURL       *url.URL
	RequestTimeout time.Duration
	LimitGrace     time.Duration
}

func Load(path string) (*Runtime, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyDefaults(&cfg)
	return validateAndResolve(cfg)
}

func applyDefaults(cfg *Config) {
	if cfg.Subscription.SampleCap == 0 {
		cfg.Subscription.SampleCap = 50
	}
	if cfg.Traffic.RelativeThreshold == 0 {
		cfg.Traffic.RelativeThreshold = 0.05
	}
	if cfg.Traffic.AbsoluteThresholdBytes == 0 {
		cfg.Traffic.AbsoluteThresholdBytes = 64 * 1024 * 1024
	}
	if cfg.Traffic.LimitGrace == "" {
		cfg.Traffic.LimitGrace = "30s"
	}
	if cfg.Transport.RequestTimeout == "" {
		cfg.Transport.RequestTimeout = "10s"
	}
	if cfg.Transport.PanelConcurrency == 0 {
		cfg.Transport.PanelConcurrency = 4
	}
	if cfg.Transport.RequestsPerPanel == 0 {
		cfg.Transport.RequestsPerPanel = 2
	}
}

func validateAndResolve(cfg Config) (*Runtime, error) {
	if cfg.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported config schema_version %d", cfg.SchemaVersion)
	}
	if len(cfg.Panels) == 0 {
		return nil, errors.New("at least one panel is required")
	}
	if cfg.Redaction.KeyEnv == "" || cfg.Redaction.KeyID == "" {
		return nil, errors.New("redaction.key_env and redaction.key_id are required")
	}
	key := []byte(os.Getenv(cfg.Redaction.KeyEnv))
	if len(key) < 32 {
		return nil, fmt.Errorf("redaction key from %s must contain at least 32 bytes", cfg.Redaction.KeyEnv)
	}
	requestTimeout, err := time.ParseDuration(cfg.Transport.RequestTimeout)
	if err != nil || requestTimeout <= 0 {
		return nil, errors.New("transport.request_timeout must be a positive duration")
	}
	limitGrace, err := time.ParseDuration(cfg.Traffic.LimitGrace)
	if err != nil || limitGrace < 0 {
		return nil, errors.New("traffic.limit_grace must be a non-negative duration")
	}
	if cfg.Subscription.SampleCap < 1 || cfg.Subscription.SampleCap > 1000 {
		return nil, errors.New("subscription.sample_cap must be between 1 and 1000")
	}
	if cfg.Traffic.RelativeThreshold <= 0 || cfg.Traffic.RelativeThreshold > 1 {
		return nil, errors.New("traffic.relative_threshold must be in (0,1]")
	}
	if cfg.Traffic.AbsoluteThresholdBytes < 1 {
		return nil, errors.New("traffic.absolute_threshold_bytes must be positive")
	}
	if cfg.Transport.PanelConcurrency < 1 || cfg.Transport.PanelConcurrency > 32 || cfg.Transport.RequestsPerPanel < 1 || cfg.Transport.RequestsPerPanel > 8 {
		return nil, errors.New("transport concurrency values are outside safe bounds")
	}

	seenIDs := map[string]bool{}
	seenGUIDs := map[string]bool{}
	seenMasterNodeGUIDs := map[string]bool{}
	masterCount := 0
	tokens := map[string]string{}
	for i := range cfg.Panels {
		p := &cfg.Panels[i]
		if !safeIdentifier(p.ID) || seenIDs[p.ID] {
			return nil, fmt.Errorf("panel id is empty or duplicated: %q", p.ID)
		}
		seenIDs[p.ID] = true
		if p.ExpectedGUID == "" || seenGUIDs[p.ExpectedGUID] {
			return nil, fmt.Errorf("panel %s expected_guid is empty or duplicated", p.ID)
		}
		seenGUIDs[p.ExpectedGUID] = true
		if p.Role == model.RoleMaster {
			masterCount++
		} else if p.Role != model.RoleNode {
			return nil, fmt.Errorf("panel %s role must be master or node", p.ID)
		} else if p.MasterNodeGUID == "" {
			return nil, fmt.Errorf("node panel %s requires master_node_guid", p.ID)
		} else if seenMasterNodeGUIDs[p.MasterNodeGUID] {
			return nil, fmt.Errorf("node panel %s duplicates master_node_guid", p.ID)
		} else {
			seenMasterNodeGUIDs[p.MasterNodeGUID] = true
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("panel %s url must be an HTTPS origin/base path without credentials, query, or fragment", p.ID)
		}
		p.URL = strings.TrimRight(p.URL, "/")
		if p.TokenEnv == "" {
			return nil, fmt.Errorf("panel %s token_env is required", p.ID)
		}
		token := os.Getenv(p.TokenEnv)
		if token == "" {
			return nil, fmt.Errorf("panel %s token environment variable %s is empty", p.ID, p.TokenEnv)
		}
		tokens[p.ID] = token
		if p.TLSPinSHA256 != "" && len(strings.TrimPrefix(strings.ToLower(p.TLSPinSHA256), "sha256:")) != 64 {
			return nil, fmt.Errorf("panel %s tls pin must be a SHA-256 hex digest", p.ID)
		}
	}
	if masterCount != 1 {
		return nil, fmt.Errorf("exactly one master panel is required, got %d", masterCount)
	}

	allowed := map[string]bool{}
	for _, host := range cfg.Transport.AllowedRedirectHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || strings.ContainsAny(host, "/@") {
			return nil, fmt.Errorf("invalid allowed redirect host %q", host)
		}
		if allowed[host] {
			return nil, fmt.Errorf("duplicate allowed redirect host %q", host)
		}
		allowed[host] = true
	}

	var proxyURL *url.URL
	if cfg.Transport.ProxyURLEnv != "" {
		raw := os.Getenv(cfg.Transport.ProxyURLEnv)
		if raw == "" {
			return nil, fmt.Errorf("proxy environment variable %s is empty", cfg.Transport.ProxyURLEnv)
		}
		proxyURL, err = url.Parse(raw)
		if err != nil || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5") || proxyURL.Host == "" {
			return nil, errors.New("configured proxy URL is invalid")
		}
	}

	return &Runtime{Config: cfg, Tokens: tokens, RedactionKey: key, ProxyURL: proxyURL, RequestTimeout: requestTimeout, LimitGrace: limitGrace}, nil
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '.' && char != '_' && char != '-' {
			return false
		}
	}
	return true
}
