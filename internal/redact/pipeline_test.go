package redact

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type scriptedAnalyzer struct {
	detection    []Finding
	verification []Finding
	calls        int
}

func (s *scriptedAnalyzer) Analyze(_ context.Context, _ string, verification bool) ([]Finding, error) {
	s.calls++
	if verification {
		return s.verification, nil
	}
	return s.detection, nil
}

func TestPipelineDeterministicAndModelRedaction(t *testing.T) {
	detector, err := NewDetector("")
	if err != nil {
		t.Fatal(err)
	}
	model := &scriptedAnalyzer{detection: []Finding{{Value: "unusual-secret-42", Category: "access token"}}}
	pipeline := NewPipeline(detector, model)
	input := "email jane@example.com from 10.1.2.3 token unusual-secret-42 repeated jane@example.com"
	result, err := pipeline.Process(context.Background(), input, Presets["light"])
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"jane@example.com", "10.1.2.3", "unusual-secret-42"} {
		if strings.Contains(result.Text, secret) {
			t.Fatalf("secret %q remained in %q", secret, result.Text)
		}
	}
	if strings.Count(result.Text, "[EMAIL_1]") != 2 {
		t.Fatalf("repeated value did not receive stable token: %q", result.Text)
	}
	if !strings.Contains(result.Text, "[ACCESS_TOKEN_1]") {
		t.Fatalf("model finding was not applied: %q", result.Text)
	}
	if len(result.Review) != 0 {
		t.Fatalf("unexpected review findings: %#v", result.Review)
	}
}

func TestVerificationBlocksAndUsesUTF16Offsets(t *testing.T) {
	detector, _ := NewDetector("")
	model := &scriptedAnalyzer{verification: []Finding{{Value: "secret-value", Category: "password"}}}
	result, err := NewPipeline(detector, model).Process(context.Background(), "😀 secret-value", Presets["light"])
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Review) != 1 {
		t.Fatalf("got %#v", result.Review)
	}
	if result.Review[0].Start != 3 || result.Review[0].End != 15 {
		t.Fatalf("expected UTF-16 offsets 3..15, got %#v", result.Review[0])
	}
}

func TestCustomRuleAndInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(path, []byte(`{"disabledBuiltins":["EMAIL"],"rules":[{"name":"TICKET_ID","pattern":"ticket=(?P<secret>[A-Z]{3}-[0-9]+)"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := NewDetector(path)
	if err != nil {
		t.Fatal(err)
	}
	found := detector.Find("jane@example.com ticket=ABC-123")
	if len(found) != 1 || found[0].category != "TICKET_ID" || found[0].value != "ABC-123" {
		t.Fatalf("unexpected matches: %#v", found)
	}

	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"rules":[{"name":"BAD","pattern":"[0-9]+"}]}`), 0o600)
	if _, err := NewDetector(bad); err == nil {
		t.Fatal("expected named-capture validation error")
	}

	unknown := filepath.Join(dir, "unknown.json")
	_ = os.WriteFile(unknown, []byte(`{"disabledBuiltins":["TYPO"]}`), 0o600)
	if _, err := NewDetector(unknown); err == nil {
		t.Fatal("expected unknown built-in validation error")
	}
}

func TestChunkingPreservesCoverage(t *testing.T) {
	text := strings.Repeat("a", 80) + "\n" + strings.Repeat("b", 80)
	chunks := splitChunks(text, 100, 10)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	if !strings.HasSuffix(chunks[0], "\n") || !strings.Contains(chunks[1], "bbbb") {
		t.Fatalf("bad chunks: %#v", chunks)
	}
	if reflect.DeepEqual(chunks[0], chunks[1]) {
		t.Fatal("chunks unexpectedly equal")
	}
}

func TestAddressPostalCodeAndSegmentedAPIKeyDetectors(t *testing.T) {
	detector, err := NewDetector("")
	if err != nil {
		t.Fatal(err)
	}
	input := "Ship to 123 North Main Street Apt 4B, Boston MA 02110 or K1A 0B1. Use sk_live/AbCDef12_34567890."
	found := detector.Find(input)
	categories := map[string]string{}
	for _, item := range found {
		categories[item.category] = item.value
	}
	for _, category := range []string{"STREET_ADDRESS", "US_ZIP_CODE", "CANADIAN_POSTAL_CODE", "API_KEY"} {
		if categories[category] == "" {
			t.Fatalf("missing %s in %#v", category, found)
		}
	}
	if categories["API_KEY"] != "sk_live/AbCDef12_34567890" {
		t.Fatalf("segmented API key was not fully captured: %#v", found)
	}
}
