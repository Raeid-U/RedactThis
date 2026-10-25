package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/raeidusmanali/redactthis/internal/config"
	"github.com/raeidusmanali/redactthis/internal/llama"
	"github.com/raeidusmanali/redactthis/internal/redact"
	webassets "github.com/raeidusmanali/redactthis/web"
)

type Server struct {
	cfg       config.Config
	pipeline  *redact.Pipeline
	llama     *llama.Client
	semaphore chan struct{}
}

func New(cfg config.Config, pipeline *redact.Pipeline, client *llama.Client) http.Handler {
	s := &Server{cfg: cfg, pipeline: pipeline, llama: client, semaphore: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/redact", s.redact)
	mux.HandleFunc("GET /api/status", s.status)
	static, _ := fs.Sub(webassets.Files, ".")
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	return s.headers(mux)
}

type redactRequest struct {
	Text       string `json:"text"`
	SizePreset string `json:"sizePreset"`
}

type redactResponse struct {
	Status          string                  `json:"status"`
	Text            string                  `json:"text"`
	Counts          map[string]int          `json:"counts"`
	ChunksProcessed int                     `json:"chunksProcessed"`
	Findings        []redact.LocatedFinding `json:"findings,omitempty"`
}

func (s *Server) redact(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-origin requests are not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var request redactRequest
	if err := dec.Decode(&request); err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeError(w, status, "invalid request body")
		return
	}
	if err := ensureEOF(dec); err != nil {
		writeError(w, http.StatusBadRequest, "request must contain one JSON object")
		return
	}
	preset, ok := redact.Presets[request.SizePreset]
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown size preset")
		return
	}
	if request.Text == "" {
		writeError(w, http.StatusBadRequest, "text is required")
		return
	}
	if utf8.RuneCountInString(request.Text) > preset.MaxChars {
		writeError(w, http.StatusRequestEntityTooLarge, "text exceeds the selected size preset")
		return
	}

	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-r.Context().Done():
		return
	}
	result, err := s.pipeline.Process(r.Context(), request.Text, preset)
	if err != nil {
		slog.Error("redaction failed", "error", err)
		writeError(w, http.StatusBadGateway, "the local model could not complete both redaction passes")
		return
	}
	response := redactResponse{Status: "verified", Text: result.Text, Counts: result.Counts, ChunksProcessed: result.ChunksProcessed}
	status := http.StatusOK
	if len(result.Review) > 0 {
		status = http.StatusUnprocessableEntity
		response.Status = "review_required"
		response.Findings = result.Review
	}
	writeJSON(w, status, response)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	err := s.llama.Health(ctx)
	status := "ready"
	httpStatus := http.StatusOK
	if err != nil {
		status = "model_unavailable"
		httpStatus = http.StatusServiceUnavailable
	}
	writeJSON(w, httpStatus, map[string]any{
		"status":  status,
		"model":   s.cfg.ModelName,
		"backend": s.cfg.Backend,
		"presets": redact.Presets,
	})
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("extra JSON content")
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
