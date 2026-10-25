package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/raeidusmanali/redactthis/internal/config"
	"github.com/raeidusmanali/redactthis/internal/llama"
	"github.com/raeidusmanali/redactthis/internal/redact"
)

func newTestHandler(t *testing.T, verificationFinding bool) http.Handler {
	t.Helper()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		var request struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		content := `{"findings":[]}`
		if verificationFinding && len(request.Messages) > 0 && strings.Contains(request.Messages[0].Content, "Independently verify") {
			content = `{"findings":[{"value":"hidden-code","category":"DEVICE_ID"}]}`
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": content}}}})
	}))
	t.Cleanup(model.Close)
	cfg := config.Config{LlamaURL: model.URL, ModelName: "test-model", Backend: "cpu", MaxBodyBytes: 2 << 20}
	client := llama.New(model.URL, cfg.ModelName, time.Second)
	detector, err := redact.NewDetector("")
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, redact.NewPipeline(detector, client), client)
}

func TestRedactAPIAndSecurityHeaders(t *testing.T) {
	handler := newTestHandler(t, false)
	req := httptest.NewRequest(http.MethodPost, "/api/redact", strings.NewReader(`{"text":"contact me@example.com","sizePreset":"light"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "me@example.com") || !strings.Contains(recorder.Body.String(), "[EMAIL_1]") {
		t.Fatalf("unexpected response: %s", recorder.Body.String())
	}
	if recorder.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP")
	}
}

func TestReviewRequiredAndCrossOriginRejection(t *testing.T) {
	handler := newTestHandler(t, true)
	req := httptest.NewRequest(http.MethodPost, "/api/redact", strings.NewReader(`{"text":"value hidden-code","sizePreset":"light"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(recorder.Body.String(), "review_required") {
		t.Fatalf("unexpected response: %d %s", recorder.Code, recorder.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/redact", strings.NewReader(`{"text":"x","sizePreset":"light"}`))
	req.Header.Set("Origin", "https://attacker.example")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestStatusReportsModel(t *testing.T) {
	handler := newTestHandler(t, false)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "test-model") {
		t.Fatalf("unexpected response: %d %s", recorder.Code, recorder.Body.String())
	}
}
