package redact

import "context"

type Finding struct {
	Value    string `json:"value"`
	Category string `json:"category"`
}

type LocatedFinding struct {
	Category string `json:"category"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

type Analyzer interface {
	Analyze(ctx context.Context, text string, verification bool) ([]Finding, error)
}

type Preset struct {
	MaxChars   int `json:"maxChars"`
	ChunkChars int `json:"chunkChars"`
}

var Presets = map[string]Preset{
	"light":    {MaxChars: 25_000, ChunkChars: 4_000},
	"balanced": {MaxChars: 100_000, ChunkChars: 6_000},
	"large":    {MaxChars: 250_000, ChunkChars: 8_000},
}

type Result struct {
	Text            string
	Counts          map[string]int
	ChunksProcessed int
	Review          []LocatedFinding
}
