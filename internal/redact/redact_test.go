package redact

import (
	"strings"
	"testing"
)

func TestAliasesAreStableAndKeyed(t *testing.T) {
	one := New([]byte(strings.Repeat("a", 32)))
	two := New([]byte(strings.Repeat("b", 32)))
	a := one.Alias("client", "alice@example.com")
	if a != one.Alias("client", "alice@example.com") {
		t.Fatal("alias is not stable")
	}
	if a == two.Alias("client", "alice@example.com") {
		t.Fatal("different keys produced the same alias")
	}
	if strings.Contains(a, "alice") || len(a) != len("client_")+12 {
		t.Fatalf("alias leaks input or has wrong length: %q", a)
	}
}

func TestSanitizedErrorCode(t *testing.T) {
	if got := SanitizedErrorCode("request deadline exceeded for secret.example"); got != "timeout" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizedErrorCode("private body text"); got != "request_error" {
		t.Fatalf("got %q", got)
	}
}
