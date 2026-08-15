package subscription

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/redact"
)

func TestParseRawBase64AndIgnoreRemark(t *testing.T) {
	r := redact.New([]byte(strings.Repeat("k", 32)))
	one := "vless://uuid@example.com:443?security=reality&flow=xtls-rprx-vision#Alice"
	two := "vless://uuid@example.com:443?flow=xtls-rprx-vision&security=reality#Different"
	encoded := base64.StdEncoding.EncodeToString([]byte(one + "\n"))
	a, err := Parse("raw", []byte(encoded), r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse("links", []byte(two), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || a[0] != b[0] {
		t.Fatalf("canonical sets differ: %v %v", a, b)
	}
}

func TestParseVMessJSONAndClash(t *testing.T) {
	r := redact.New([]byte(strings.Repeat("k", 32)))
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"Alice","add":"example.com","port":"443","id":"uuid"}`))
	if _, err := Parse("raw", []byte("vmess://"+vmess), r); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("json", []byte(`[{"protocol":"vless","address":"example.com"}]`), r); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("clash", []byte("proxies:\n  - name: test\n    type: vless\n    server: example.com\n"), r); err != nil {
		t.Fatal(err)
	}
}

func TestParseShadowsocksRepresentations(t *testing.T) {
	r := redact.New([]byte(strings.Repeat("k", 32)))
	credential := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:password"))
	standard, err := Parse("raw", []byte("ss://"+credential+"@example.com:443#one"), r)
	if err != nil {
		t.Fatal(err)
	}
	legacyPayload := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:password@example.com:443"))
	legacy, err := Parse("raw", []byte("ss://"+legacyPayload+"#two"), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(standard) != 1 || standard[0] != legacy[0] {
		t.Fatalf("Shadowsocks forms were not canonicalized equally: %v %v", standard, legacy)
	}
}

func TestMalformedInputsFailClosed(t *testing.T) {
	r := redact.New([]byte(strings.Repeat("k", 32)))
	invalidVMess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2"}`))
	for _, test := range []struct{ format, body string }{{"raw", "not base64"}, {"raw", "vless://missing-endpoint"}, {"raw", invalidVMess}, {"raw", "ss://bm8tZW5kcG9pbnQ"}, {"json", "{"}, {"clash", "[unterminated"}} {
		if _, err := Parse(test.format, []byte(test.body), r); err == nil {
			t.Fatalf("accepted malformed %s", test.format)
		}
	}
}

func FuzzParseRaw(f *testing.F) {
	f.Add("vless://uuid@example.com:443?security=tls#name")
	f.Add("%%%")
	r := redact.New([]byte(strings.Repeat("f", 32)))
	f.Fuzz(func(t *testing.T, input string) { _, _ = Parse("raw", []byte(input), r) })
}
