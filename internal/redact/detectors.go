package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type rule struct {
	name     string
	re       *regexp.Regexp
	priority int
	valid    func(string) bool
}

type RulesFile struct {
	DisabledBuiltins []string     `json:"disabledBuiltins"`
	Rules            []CustomRule `json:"rules"`
}

type CustomRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

type Detector struct{ rules []rule }

type match struct {
	start, end int
	category   string
	value      string
	priority   int
}

func NewDetector(rulesPath string) (*Detector, error) {
	builtins := []rule{
		compileRule("PRIVATE_KEY", `(?s)(?P<secret>-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----)`, 100, nil),
		compileRule("API_KEY", `(?P<secret>AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})`, 95, nil),
		compileRule("JWT", `(?P<secret>eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})`, 94, nil),
		compileRule("CREDENTIAL", `(?i)(?:password|passwd|pwd|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret)\s*[:=]\s*["']?(?P<secret>[^\s"',;]{4,})`, 90, nil),
		compileRule("URL_SECRET", `(?i)(?:[?&](?:api[_-]?key|token|access[_-]?token|password|secret)=)(?P<secret>[^&#\s"',;]{4,})`, 89, nil),
		compileRule("DEVICE_ID", `(?i)(?:serial(?:_number)?|device[_-]?id|imei|meid)\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9._:-]{5,})`, 88, nil),
		compileRule("EMAIL", `(?P<secret>[A-Za-z0-9.!#$%&'*+/=?^_`+"`"+`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)`, 70, nil),
		compileRule("MAC_ADDRESS", `(?P<secret>(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})`, 70, nil),
		compileRule("UUID", `(?P<secret>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-8][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12})`, 70, nil),
		compileRule("IP_ADDRESS", `(?P<secret>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)`, 65, func(s string) bool { return net.ParseIP(s) != nil }),
		compileRule("PHONE_NUMBER", `(?P<secret>\+?[0-9][0-9 .()-]{7,}[0-9])`, 40, validPhone),
		compileRule("PAYMENT_CARD", `(?P<secret>[0-9](?:[ -]?[0-9]){12,18})`, 35, validCard),
	}

	if rulesPath == "" {
		return &Detector{rules: builtins}, nil
	}
	b, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var cfg RulesFile
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	knownBuiltins := map[string]bool{}
	for _, r := range builtins {
		knownBuiltins[r.name] = true
	}
	disabled := map[string]bool{}
	for _, name := range cfg.DisabledBuiltins {
		normalized := normalizeCategory(name)
		if !knownBuiltins[normalized] {
			return nil, fmt.Errorf("unknown built-in detector %q", name)
		}
		disabled[normalized] = true
	}
	filtered := builtins[:0]
	for _, r := range builtins {
		if !disabled[r.name] {
			filtered = append(filtered, r)
		}
	}
	seen := map[string]bool{}
	for _, r := range filtered {
		seen[r.name] = true
	}
	for _, custom := range cfg.Rules {
		name := normalizeCategory(custom.Name)
		if name == "" || seen[name] {
			return nil, fmt.Errorf("custom rule has invalid or duplicate name %q", custom.Name)
		}
		re, err := regexp.Compile(custom.Pattern)
		if err != nil {
			return nil, fmt.Errorf("custom rule %s: %w", name, err)
		}
		if re.SubexpIndex("secret") < 1 {
			return nil, fmt.Errorf("custom rule %s must contain a named capture group 'secret'", name)
		}
		filtered = append(filtered, rule{name: name, re: re, priority: 110})
		seen[name] = true
	}
	return &Detector{rules: filtered}, nil
}

func compileRule(name, pattern string, priority int, valid func(string) bool) rule {
	return rule{name: name, re: regexp.MustCompile(pattern), priority: priority, valid: valid}
}

func normalizeCategory(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(r)
		} else if r == '-' || unicode.IsSpace(r) {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func (d *Detector) Find(text string) []match {
	var found []match
	for _, r := range d.rules {
		secretIndex := r.re.SubexpIndex("secret")
		for _, indexes := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := indexes[secretIndex*2], indexes[secretIndex*2+1]
			if start < 0 || end <= start {
				continue
			}
			value := text[start:end]
			if r.valid != nil && !r.valid(value) {
				continue
			}
			found = append(found, match{start: start, end: end, category: r.name, value: value, priority: r.priority})
		}
	}
	return selectNonOverlapping(found)
}

func selectNonOverlapping(found []match) []match {
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].priority != found[j].priority {
			return found[i].priority > found[j].priority
		}
		return found[i].end-found[i].start > found[j].end-found[j].start
	})
	selected := make([]match, 0, len(found))
	for _, candidate := range found {
		overlaps := false
		for _, accepted := range selected {
			if candidate.start < accepted.end && accepted.start < candidate.end {
				overlaps = true
				break
			}
		}
		if !overlaps {
			selected = append(selected, candidate)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].start < selected[j].start })
	return selected
}

func validPhone(s string) bool {
	digits := 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			digits++
		}
	}
	return digits >= 8 && digits <= 15
}

func validCard(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, parity := 0, len(digits)%2
	for i, d := range digits {
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
