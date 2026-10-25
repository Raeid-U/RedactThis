package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/raeidusmanali/redactthis/internal/config"
	"github.com/raeidusmanali/redactthis/internal/llama"
	"github.com/raeidusmanali/redactthis/internal/redact"
	"github.com/raeidusmanali/redactthis/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	detector, err := redact.NewDetector(cfg.RulesPath)
	if err != nil {
		slog.Error("invalid redaction rules", "error", err)
		os.Exit(1)
	}
	client := llama.New(cfg.LlamaURL, cfg.ModelID, cfg.Timeout)
	handler := server.New(cfg, redact.NewPipeline(detector, client), client)
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	slog.Info("RedactThis listening", "address", cfg.ListenAddr, "backend", cfg.Backend, "model", cfg.ModelName)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
