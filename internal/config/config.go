package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port    string
	OllamaBaseURL   string
	OllamaJudgeModel string
	OllamaProxyModel string

	// Entropy thresholds
	EntropyHighThreshold       float64
	EntropySuspiciousThreshold float64

	// Sliding window token budget
	TokenBudgetPerHour int

	// Penalty TTL in minutes
	PenaltyTTLMinutes int

	// Rate limit: requests per minute per fingerprint
	RateLimitRPM int

	// Optional API key to protect the proxy itself
	APIKey string
}

func Load() *Config {
	return &Config{
		Port:                       getEnv("PORT", "8080"),
		OllamaBaseURL:              getEnv("OLLAMA_BASE_URL", "http://localhost:11434"),
		OllamaJudgeModel:           getEnv("OLLAMA_JUDGE_MODEL", "llama3"),
		OllamaProxyModel:           getEnv("OLLAMA_PROXY_MODEL", "llama3"),
		EntropyHighThreshold:       getEnvFloat("ENTROPY_HIGH_THRESHOLD", 6.5),
		EntropySuspiciousThreshold: getEnvFloat("ENTROPY_SUSPICIOUS_THRESHOLD", 5.5),
		TokenBudgetPerHour:         getEnvInt("TOKEN_BUDGET_PER_HOUR", 50000),
		PenaltyTTLMinutes:          getEnvInt("PENALTY_TTL_MINUTES", 60),
		RateLimitRPM:               getEnvInt("RATE_LIMIT_RPM", 60),
		APIKey:                     getEnv("AEGIS_API_KEY", ""),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
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
