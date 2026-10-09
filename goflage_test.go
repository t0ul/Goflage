package goflage

import (
	"strings"
	"testing"
)

func TestScrubRedactsSecretsAndPII(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		secret string // substring that MUST NOT survive
		entity string // an entity we expect among findings
	}{
		{"aws_secret_assignment", "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI", "SECRET_KEY"},
		{"aws_key_id", "key is AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"},
		{"session_token", "export SESSION_TOKEN=eyJhbGciOiJIUzI.eyJzdWIiOiIx.abc123", "eyJhbGciOiJIUzI", "SECRET_KEY"},
		{"openai_token", "OPENAI_API_KEY=sk-ABCD1234efgh5678ijkl", "sk-ABCD1234efgh5678ijkl", "SECRET_KEY"},
		{"email", "ping jane.doe@example.org for access", "jane.doe@example.org", "EMAIL_ADDRESS"},
		{"ip", "server at 10.0.0.5 responded", "10.0.0.5", "IP_ADDRESS"},
		{"credit_card_luhn", "card 4242 4242 4242 4242 on file", "4242 4242 4242 4242", "CREDIT_CARD"},
		{"bearer", "Authorization: Bearer abcDEF123456.ghiJKL", "abcDEF123456.ghiJKL", "BEARER"},
	}
	a := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clean, findings := a.Scrub(c.in)
			if strings.Contains(clean, c.secret) {
				t.Fatalf("secret survived scrub: %q still in %q", c.secret, clean)
			}
			found := false
			for _, f := range findings {
				if f.Entity == c.entity {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a %s finding; got %+v", c.entity, findings)
			}
		})
	}
}

func TestNoFalsePositives(t *testing.T) {
	clean := []string{
		"git checkout a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4", // 40-hex SHA, not a key/CC
		"ran uname -a and ls -la /var/log today",               // plain commands
		"invoice number 1234 5678 9012 3456 attached",          // 16 digits, fails Luhn -> not a CC
		"version 3.7.4 of the library",                         // not an IP
	}
	a := New()
	for _, in := range clean {
		if out, findings := a.Scrub(in); len(findings) != 0 {
			t.Errorf("false positive on %q: %+v -> %q", in, findings, out)
		}
	}
}

func TestLuhn(t *testing.T) {
	if !luhnValid("4242 4242 4242 4242") {
		t.Error("known-valid test card rejected")
	}
	if luhnValid("1234 5678 9012 3456") {
		t.Error("invalid number accepted as a card")
	}
}

// TestScrubRedactsSSN covers the US SSN recognizer + its SSA-rules validity gate: a
// valid dashed SSN is redacted; an invalid-range one (and a non-SSN 3-2-4 string) is not
// falsely scrubbed.
func TestScrubRedactsSSN(t *testing.T) {
	out, finds := New().Scrub("Student SSN 123-45-6789 on file.")
	if strings.Contains(out, "123-45-6789") {
		t.Errorf("valid SSN must be redacted, got %q", out)
	}
	var sawSSN bool
	for _, f := range finds {
		if f.Entity == "US_SSN" {
			sawSSN = true
		}
	}
	if !sawSSN {
		t.Errorf("expected a US_SSN finding, got %+v", finds)
	}
	// Invalid area (900+) must NOT be scrubbed as an SSN.
	if out, _ := New().Scrub("code 900-45-6789 here"); !strings.Contains(out, "900-45-6789") {
		t.Errorf("an invalid-range SSN must not be scrubbed, got %q", out)
	}
	// Area 000 is never issued.
	if out, _ := New().Scrub("ref 000-12-3456 end"); !strings.Contains(out, "000-12-3456") {
		t.Errorf("area 000 must not be scrubbed, got %q", out)
	}
}
