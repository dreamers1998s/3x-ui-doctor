package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/collect"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/config"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/diff"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/report"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/rules"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/snapshot"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/version"
)

type CommonFlags struct {
	Config  string
	Format  string
	Output  string
	Observe time.Duration
	Force   bool
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 3
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(stdout, version.Version)
		return 0
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := CommonFlags{}
	fs.StringVar(&common.Config, "config", "doctor.yaml", "path to doctor.yaml")
	fs.StringVar(&common.Format, "format", "terminal", "terminal, json, or markdown")
	fs.StringVar(&common.Output, "output", "-", "output path or - for stdout")
	fs.DurationVar(&common.Observe, "observe", 60*time.Second, "traffic observation window")
	fs.BoolVar(&common.Force, "force", false, "replace an existing output file")
	var target, baselineOut, baselinePath string
	switch command {
	case "preflight":
		fs.StringVar(&target, "target", "", "target 3x-ui version or stable")
		fs.StringVar(&baselineOut, "baseline-out", "", "secure output path for the baseline snapshot")
	case "verify":
		fs.StringVar(&baselinePath, "baseline", "", "preflight baseline JSON")
	case "check":
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", command)
		usage(stderr)
		return 3
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 3
	}
	if fs.NArg() != 0 || common.Observe < 0 {
		fmt.Fprintln(stderr, "unexpected arguments or negative observation duration")
		return 3
	}
	if common.Format != "terminal" && common.Format != "json" && common.Format != "markdown" {
		fmt.Fprintln(stderr, "--format must be terminal, json, or markdown")
		return 3
	}

	runtime, err := config.Load(common.Config)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return 3
	}
	var before model.Snapshot
	if command == "preflight" {
		if target == "" || baselineOut == "" {
			fmt.Fprintln(stderr, "preflight requires --target and --baseline-out")
			return 3
		}
		if sameOutputPath(baselineOut, common.Output) {
			fmt.Fprintln(stderr, "baseline and report output paths must differ")
			return 3
		}
		target, err = resolveTarget(ctx, target, runtime.ProxyURL)
		if err != nil {
			fmt.Fprintf(stderr, "target error: %v\n", err)
			return 3
		}
		if target != "v3.6.0" {
			fmt.Fprintln(stderr, "v0.1 only guarantees target v3.6.0")
			return 3
		}
	}
	if command == "verify" {
		if baselinePath == "" {
			fmt.Fprintln(stderr, "verify requires --baseline")
			return 3
		}
		if sameOutputPath(baselinePath, common.Output) {
			fmt.Fprintln(stderr, "baseline and report output paths must differ")
			return 3
		}
		before, err = snapshot.Read(baselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "baseline error: %v\n", err)
			return 3
		}
		if before.Manifest.RedactionKeyID != runtime.Config.Redaction.KeyID {
			fmt.Fprintln(stderr, "baseline redaction key id does not match configuration")
			return 3
		}
		target = before.Manifest.TargetVersion
		if target != "v3.6.0" {
			fmt.Fprintln(stderr, "baseline target is outside the v0.1 compatibility guarantee")
			return 3
		}
	}

	collector, err := collect.New(runtime)
	if err != nil {
		fmt.Fprintf(stderr, "collector initialization error: %v\n", err)
		return 3
	}
	after, err := collector.Collect(ctx, command, target, common.Observe)
	if err != nil {
		fmt.Fprintf(stderr, "collection interrupted: %v\n", err)
		return 3
	}
	findings := rules.Evaluate(after, rules.Options{RelativeThreshold: runtime.Config.Traffic.RelativeThreshold, AbsoluteThreshold: runtime.Config.Traffic.AbsoluteThresholdBytes, LimitGrace: runtime.LimitGrace})
	var changes []model.Change
	if command == "verify" {
		var regressions []model.Finding
		changes, regressions = diff.Compare(before, after)
		findings = append(findings, regressions...)
	}
	result := model.Result{SchemaVersion: model.ResultSchemaVersion, Manifest: after.Manifest, PanelCount: len(after.Panels), Findings: findings, Changes: changes, Sensitive: after.Sensitive}
	result.Readiness = rules.Readiness(findings)

	if command == "preflight" {
		if err := snapshot.WriteJSON(baselineOut, after, common.Force); err != nil {
			fmt.Fprintf(stderr, "baseline output error: %v\n", err)
			return 3
		}
	}
	body, err := report.Render(common.Format, result)
	if err != nil {
		fmt.Fprintf(stderr, "report error: %v\n", err)
		return 3
	}
	if common.Output == "-" {
		if _, err := stdout.Write(body); err != nil {
			fmt.Fprintln(stderr, "write report failed")
			return 3
		}
	} else if err := snapshot.Write(common.Output, body, common.Force); err != nil {
		fmt.Fprintf(stderr, "report output error: %v\n", err)
		return 3
	}
	return ExitCode(result.Readiness)
}

func ExitCode(readiness model.Readiness) int {
	switch readiness {
	case model.Ready:
		return 0
	case model.Blocked:
		return 1
	case model.Inconclusive:
		return 2
	default:
		return 3
	}
}

func resolveTarget(ctx context.Context, value string, proxyURL *url.URL) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value != "stable" {
		if !strings.HasPrefix(value, "v") {
			value = "v" + value
		}
		return value, nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "3x-ui-doctor/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("official stable release metadata is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("official release metadata returned HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, 1<<20)
	var release struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(limited).Decode(&release); err != nil || release.Tag == "" {
		return "", errors.New("official release metadata is invalid")
	}
	return strings.ToLower(release.Tag), nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: xui-doctor <preflight|verify|check|version> [options]")
}

func sameOutputPath(a, b string) bool {
	if a == "" || b == "" || a == "-" || b == "-" {
		return false
	}
	a, errA := filepath.Abs(filepath.Clean(a))
	b, errB := filepath.Abs(filepath.Clean(b))
	if errA != nil || errB != nil {
		return a == b
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Ensure command tests can replace process streams without touching globals.
var _ = os.Stderr
