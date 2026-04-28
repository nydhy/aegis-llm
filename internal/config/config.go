package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port string

	// Proxy LLM — where user requests are forwarded (any OpenAI-compatible endpoint)
	LLMBaseURL string
	LLMAPIKey  string
	LLMModel   string

	// Judge LLM — optional, for evaluating SUSPICIOUS entropy prompts
	// Defaults to same provider as proxy LLM if not set separately
	JudgeEnabled bool
	JudgeBaseURL string
	JudgeAPIKey  string
	JudgeModel   string

	// Entropy thresholds
	EntropyHighThreshold       float64
	EntropySuspiciousThreshold float64

	// Sliding window token budget per user per hour
	TokenBudgetPerHour int

	// How long a flagged fingerprint stays in the penalty box
	PenaltyTTL time.Duration

	// Rate limit: requests per minute per user fingerprint
	RateLimitRPM int

	// Optional Bearer token to protect the proxy itself
	APIKey string

	// DemoMode starts an in-process stub LLM — no external dependencies needed
	DemoMode bool
}

func Load() *Config {
	cfg := &Config{
		Port:                       getEnv("PORT", "8080"),
		LLMBaseURL:                 getEnv("LLM_BASE_URL", "http://localhost:11434/v1"),
		LLMAPIKey:                  getEnv("LLM_API_KEY", ""),
		LLMModel:                   getEnv("LLM_MODEL", "llama3"),
		JudgeEnabled:               getEnvBool("JUDGE_ENABLED", false),
		JudgeModel:                 getEnv("JUDGE_MODEL", "llama3"),
		EntropyHighThreshold:       getEnvFloat("ENTROPY_HIGH_THRESHOLD", 6.5),
		EntropySuspiciousThreshold: getEnvFloat("ENTROPY_SUSPICIOUS_THRESHOLD", 5.5),
		TokenBudgetPerHour:         getEnvInt("TOKEN_BUDGET_PER_HOUR", 50000),
		PenaltyTTL:                 time.Duration(getEnvInt("PENALTY_TTL_MINUTES", 60)) * time.Minute,
		RateLimitRPM:               getEnvInt("RATE_LIMIT_RPM", 60),
		APIKey:                     getEnv("AEGIS_API_KEY", ""),
		DemoMode:                   getEnvBool("DEMO_MODE", false),
	}

	// Judge can share the proxy provider or use a dedicated one
	cfg.JudgeBaseURL = getEnv("JUDGE_BASE_URL", cfg.LLMBaseURL)
	cfg.JudgeAPIKey = getEnv("JUDGE_API_KEY", cfg.LLMAPIKey)

	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "true" || v == "1" || v == "yes"
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}
