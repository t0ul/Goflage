// Package goflage is a dependency-free PII/secret scrubber — a Go-native,
// pure-stdlib alternative to Microsoft Presidio for the deterministic,
// high-precision cases.
//
// It detects and redacts emails, IPs, Luhn-validated credit cards, AWS access
// keys, env-style secret assignments, API tokens, JWTs and bearer tokens using
// regex + checksum recognizers. Named-entity recognition (PERSON, LOCATION, …)
// is intentionally out of scope: that belongs behind a served model. goflage
// owns the parts you want deterministic, fast, and with zero dependencies.
package goflage

import (
	"regexp"
	"sort"
	"strings"
)

// Match is a single detected entity span in the source text.
type Match struct {
	Entity string
	Start  int
	End    int
	Text   string
	Score  float64
}

// Finding is a telemetry-safe summary: WHAT was found and how often, never the
// value. Log Findings, never Matches — the audit trail must not become the leak.
type Finding struct {
	Entity string
	Count  int
}

type recognizer struct {
	entity   string
	re       *regexp.Regexp
	score    float64
	validate func(string) bool // optional checksum/confirmation gate
}

var recognizers = []recognizer{
	{"SECRET_KEY", regexp.MustCompile(`(?i)\b\w*(?:secret|passwd|password|token|apikey|api[_-]?key|access[_-]?key|credential|private[_-]?key|username|login)\w*[^\n:=]{0,24}[:=]\s*\S+`), 0.90, nil},
	{"AWS_ACCESS_KEY", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b`), 0.90, nil},
	{"API_TOKEN", regexp.MustCompile(`\b(?:sk|pk|rk|ghp|gho|ghs|xox[baprs])[-_][A-Za-z0-9]{16,}\b`), 0.85, nil},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`), 0.90, nil},
	{"BEARER", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{10,}\b`), 0.85, nil},
	{"EMAIL_ADDRESS", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), 0.80, nil},
	{"IP_ADDRESS", regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`), 0.70, nil},
	// Credit card: broad regex, confirmed by Luhn — this checksum gate is why we
	// get far fewer false positives than a regex-only scrubber.
	{"CREDIT_CARD", regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), 0.90, luhnValid},
	// US SSN (dashed form): the SSA issuance rules gate out invalid ranges so a stray
	// 3-2-4 digit group (a product code, a phone) is not scrubbed as an SSN. Scored
	// above CREDIT_CARD so it wins any overlap (an SSN is 9 digits, not a card anyway).
	{"US_SSN", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), 0.95, ssnValid},
}

// ssnValid applies the SSA issuance rules to a dashed SSN: area 000, 666 and 900–999 are
// never assigned, the group is 01–99, and the serial is 0001–9999. This confirmation
// gate keeps a random 3-2-4 digit string from being scrubbed as an SSN.
func ssnValid(s string) bool {
	if len(s) != 11 || s[3] != '-' || s[6] != '-' {
		return false
	}
	area := s[0:3]
	group := s[4:6]
	serial := s[7:11]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// Analyzer detects entities. Use New() for the default recognizer set.
type Analyzer struct{ recs []recognizer }

// New returns an Analyzer with the default recognizers.
func New() *Analyzer { return &Analyzer{recs: recognizers} }

// Analyze returns non-overlapping matches, strongest kept on conflict.
func (a *Analyzer) Analyze(text string) []Match {
	var ms []Match
	for _, r := range a.recs {
		for _, loc := range r.re.FindAllStringIndex(text, -1) {
			val := text[loc[0]:loc[1]]
			if r.validate != nil && !r.validate(val) {
				continue
			}
			ms = append(ms, Match{r.entity, loc[0], loc[1], val, r.score})
		}
	}
	return resolveOverlaps(ms)
}

// Anonymize replaces each match span with "<ENTITY>". Matches may be in any
// order; overlaps are skipped defensively.
func Anonymize(text string, ms []Match) string {
	sorted := append([]Match(nil), ms...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Start < sorted[j].Start })
	var b strings.Builder
	last := 0
	for _, m := range sorted {
		if m.Start < last {
			continue
		}
		b.WriteString(text[last:m.Start])
		b.WriteString("<" + m.Entity + ">")
		last = m.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// Scrub is the high-level API: returns the redacted text and a telemetry-safe
// summary of what was removed (entity types + counts, never values).
func (a *Analyzer) Scrub(text string) (string, []Finding) {
	ms := a.Analyze(text)
	counts := map[string]int{}
	for _, m := range ms {
		counts[m.Entity]++
	}
	fs := make([]Finding, 0, len(counts))
	for e, c := range counts {
		fs = append(fs, Finding{e, c})
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].Entity < fs[j].Entity })
	return Anonymize(text, ms), fs
}

// resolveOverlaps keeps the strongest (then longest) match on any overlap.
func resolveOverlaps(ms []Match) []Match {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Score != ms[j].Score {
			return ms[i].Score > ms[j].Score
		}
		return (ms[i].End - ms[i].Start) > (ms[j].End - ms[j].Start)
	})
	var kept []Match
	for _, m := range ms {
		overlap := false
		for _, k := range kept {
			if m.Start < k.End && k.Start < m.End {
				overlap = true
				break
			}
		}
		if !overlap {
			kept = append(kept, m)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}

// luhnValid reports whether the digits in s (13–19 of them) pass the Luhn check.
func luhnValid(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	for i, d := range digits {
		if (len(digits)-1-i)%2 == 1 { // double every second digit from the right
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
