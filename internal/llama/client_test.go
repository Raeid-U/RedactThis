package llama

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAnalyzeUsesChatSchemaAndParsesFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		messages, ok := request["messages"].([]any)
		if !ok || len(messages) != 2 {
			t.Fatalf("unexpected messages: %#v", request["messages"])
		}
		first := messages[0].(map[string]any)
		if first["role"] != "system" {
			t.Fatalf("message fields were not OpenAI-compatible: %#v", first)
		}
		if request["response_format"] == nil {
			t.Fatal("missing response schema")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"findings\":[{\"value\":\"abc123\",\"category\":\"TOKEN\"}]}"}}]}`))
	}))
	defer server.Close()
	client := New(server.URL, "test", time.Second)
	findings, err := client.Analyze(context.Background(), "abc123", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Value != "abc123" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}
