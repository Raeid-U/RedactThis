package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr   string
	LlamaURL     string
	ModelName    string
	ModelID      string
	Backend      string
	RulesPath    string
	Timeout      time.Duration
	MaxBodyBytes int64
}

func Load() (Config, error) {
	timeout, err := time.ParseDuration(env("MODEL_TIMEOUT", "10m"))
	if err != nil {
		return Config{}, fmt.Errorf("MODEL_TIMEOUT: %w", err)
	}
	maxBody, err := strconv.ParseInt(env("MAX_BODY_BYTES", "2097152"), 10, 64)
	if err != nil || maxBody < 1 {
		return Config{}, fmt.Errorf("MAX_BODY_BYTES must be a positive integer")
	}
	return Config{
		ListenAddr:   env("LISTEN_ADDR", ":8080"),
		LlamaURL:     env("LLAMA_URL", "http://llama-cpu:8080"),
		ModelName:    env("MODEL_NAME", "SmolLM2"),
		ModelID:      os.Getenv("LLAMA_MODEL_ID"),
		Backend:      env("ACCELERATOR", "cpu"),
		RulesPath:    os.Getenv("RULES_FILE"),
		Timeout:      timeout,
		MaxBodyBytes: maxBody,
	}, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
