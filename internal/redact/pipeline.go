package redact

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

type Pipeline struct {
	detector *Detector
	analyzer Analyzer
}

func NewPipeline(detector *Detector, analyzer Analyzer) *Pipeline {
	return &Pipeline{detector: detector, analyzer: analyzer}
}

type replacementState struct {
	byValue  map[string]string
	counters map[string]int
	counts   map[string]int
}

func newReplacementState() *replacementState {
	return &replacementState{byValue: map[string]string{}, counters: map[string]int{}, counts: map[string]int{}}
}

func (p *Pipeline) Process(ctx context.Context, input string, preset Preset) (Result, error) {
	state := newReplacementState()
	draft := applyMatches(input, p.detector.Find(input), state)
	chunks := splitChunks(draft, preset.ChunkChars, 256)

	var candidates []Finding
	for _, chunk := range chunks {
		found, err := p.analyzer.Analyze(ctx, chunk, false)
		if err != nil {
			return Result{}, fmt.Errorf("redaction model pass: %w", err)
		}
		candidates = append(candidates, found...)
	}
	draft = applyModelFindings(draft, candidates, state)

	verificationChunks := splitChunks(draft, preset.ChunkChars, 256)
	var review []LocatedFinding
	for _, chunk := range verificationChunks {
		found, err := p.analyzer.Analyze(ctx, chunk, true)
		if err != nil {
			return Result{}, fmt.Errorf("verification model pass: %w", err)
		}
		review = append(review, locateFindings(draft, found)...)
	}
	review = dedupeLocations(review)
	return Result{Text: draft, Counts: state.counts, ChunksProcessed: len(chunks) + len(verificationChunks), Review: review}, nil
}

func applyMatches(text string, matches []match, state *replacementState) string {
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		if m.start < last {
			continue
		}
		b.WriteString(text[last:m.start])
		b.WriteString(state.placeholder(m.value, m.category, text))
		state.counts[m.category]++
		last = m.end
	}
	b.WriteString(text[last:])
	return b.String()
}

func (s *replacementState) placeholder(value, category, document string) string {
	if existing, ok := s.byValue[value]; ok {
		return existing
	}
	category = normalizeCategory(category)
	if category == "" {
		category = "SENSITIVE_VALUE"
	}
	for {
		s.counters[category]++
		candidate := fmt.Sprintf("[%s_%d]", category, s.counters[category])
		if !strings.Contains(document, candidate) {
			s.byValue[value] = candidate
			return candidate
		}
	}
}

func applyModelFindings(text string, findings []Finding, state *replacementState) string {
	unique := map[string]Finding{}
	for _, f := range findings {
		f.Value = strings.TrimSpace(f.Value)
		f.Category = normalizeCategory(f.Category)
		valueLength := utf8.RuneCountInString(f.Value)
		if valueLength < 4 || valueLength > 512 || f.Category == "" || strings.HasPrefix(f.Value, "[") && strings.HasSuffix(f.Value, "]") || !strings.Contains(text, f.Value) {
			continue
		}
		unique[f.Value] = f
	}
	var matches []match
	for value, f := range unique {
		for start := 0; ; {
			i := strings.Index(text[start:], value)
			if i < 0 {
				break
			}
			i += start
			matches = append(matches, match{start: i, end: i + len(value), value: value, category: f.Category, priority: 50})
			start = i + len(value)
		}
	}
	return applyMatches(text, selectNonOverlapping(matches), state)
}

func locateFindings(text string, findings []Finding) []LocatedFinding {
	var out []LocatedFinding
	for _, f := range findings {
		category := normalizeCategory(f.Category)
		if category == "" {
			category = "SENSITIVE_VALUE"
		}
		value := strings.TrimSpace(f.Value)
		located := false
		if value != "" && !(strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]")) {
			for start := 0; ; {
				i := strings.Index(text[start:], value)
				if i < 0 {
					break
				}
				i += start
				out = append(out, LocatedFinding{Category: category, Start: jsOffset(text[:i]), End: jsOffset(text[:i+len(value)])})
				located = true
				start = i + len(value)
			}
		}
		if !located {
			out = append(out, LocatedFinding{Category: category, Start: -1, End: -1})
		}
	}
	return out
}

// JavaScript textarea selection offsets are UTF-16 code units, not UTF-8 bytes.
func jsOffset(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xffff {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func dedupeLocations(in []LocatedFinding) []LocatedFinding {
	seen := map[string]bool{}
	out := make([]LocatedFinding, 0, len(in))
	for _, f := range in {
		key := fmt.Sprintf("%s:%d:%d", f.Category, f.Start, f.End)
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

func splitChunks(text string, limit, overlap int) []string {
	runes := []rune(text)
	if len(runes) <= limit {
		return []string{text}
	}
	if overlap >= limit {
		overlap = limit / 10
	}
	var out []string
	for start := 0; start < len(runes); {
		end := start + limit
		if end >= len(runes) {
			out = append(out, string(runes[start:]))
			break
		}
		floor := start + limit*3/4
		for i := end; i > floor; i-- {
			if runes[i-1] == '\n' {
				end = i
				break
			}
		}
		out = append(out, string(runes[start:end]))
		next := end - overlap
		if next <= start {
			next = end
		}
		start = next
	}
	return out
}
