package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
	"github.com/3x-ui-doctor/3x-ui-doctor/internal/version"
)

func TestVersionAndUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exit code %d", code)
	}
	if strings.TrimSpace(stdout.String()) != version.Version {
		t.Fatalf("unexpected version %q", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(context.Background(), []string{"unknown"}, &stdout, &stderr); code != 3 {
		t.Fatalf("unknown command exit code %d", code)
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatal("usage was not printed")
	}
}

func TestExitCodes(t *testing.T) {
	for readiness, expected := range map[model.Readiness]int{model.Ready: 0, model.Blocked: 1, model.Inconclusive: 2, "BROKEN": 3} {
		if got := ExitCode(readiness); got != expected {
			t.Fatalf("%s: got %d want %d", readiness, got, expected)
		}
	}
}

func TestEquivalentOutputPathsAreDetected(t *testing.T) {
	if !sameOutputPath("reports/result.json", "reports/./result.json") {
		t.Fatal("equivalent output paths were not detected")
	}
	if sameOutputPath("-", "-") || sameOutputPath("a.json", "b.json") {
		t.Fatal("distinct output paths were rejected")
	}
}
