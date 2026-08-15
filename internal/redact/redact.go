package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type Redactor struct {
	key []byte
}

func New(key []byte) *Redactor {
	copyKey := append([]byte(nil), key...)
	return &Redactor{key: copyKey}
}

func (r *Redactor) Alias(kind, value string) string {
	if value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, r.key)
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return kind + "_" + hex.EncodeToString(mac.Sum(nil))[:12]
}

func (r *Redactor) Digest(value string) string {
	mac := hmac.New(sha256.New, r.key)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func HashBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func SanitizedErrorCode(message string) string {
	m := strings.ToLower(message)
	switch {
	case strings.Contains(m, "timeout") || strings.Contains(m, "deadline"):
		return "timeout"
	case strings.Contains(m, "certificate") || strings.Contains(m, "tls"):
		return "tls_error"
	case strings.Contains(m, "unauthorized") || strings.Contains(m, "forbidden"):
		return "authentication_error"
	case strings.Contains(m, "redirect"):
		return "redirect_rejected"
	case strings.Contains(m, "json") || strings.Contains(m, "yaml") || strings.Contains(m, "decode"):
		return "parse_error"
	default:
		return "request_error"
	}
}
