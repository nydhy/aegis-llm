package proxy

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nydhy/aegis-llm/internal/config"
	"github.com/nydhy/aegis-llm/internal/ollama"
	"github.com/nydhy/aegis-llm/internal/penalty"
	"github.com/nydhy/aegis-llm/internal/pipeline"
	"github.com/nydhy/aegis-llm/internal/ratelimit"
)

type Server struct {
	router  *gin.Engine
	cfg     *config.Config
	ollama  *ollama.Client
	penalty *penalty.Store
	budget  *ratelimit.SlidingWindowLimiter
}

type ChatRequest struct {
	Model    string             `json:"model"`
	Messages []ollama.Message   `json:"messages"`
	Stream   bool               `json:"stream"`
}

type ShieldMeta struct {
	Fingerprint  string  `json:"fingerprint"`
	ThreatLevel  string  `json:"threat_level"`
	Entropy      float64 `json:"entropy"`
	TokensUsed   int     `json:"tokens_used_this_window"`
	BudgetLimit  int     `json:"budget_limit"`
	Penalised    bool    `json:"penalised"`
	BlockReason  string  `json:"block_reason,omitempty"`
	ResponseTime string  `json:"response_time"`
}

type ChatResponse struct {
	Model   string `json:"model"`
	Message ollama.Message `json:"message"`
	Aegis   ShieldMeta     `json:"aegis"`
}

func NewServer(cfg *config.Config) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	s := &Server{
		router:  r,
		cfg:     cfg,
		ollama:  ollama.NewClient(cfg.OllamaBaseURL),
		penalty: penalty.NewStore(time.Duration(cfg.PenaltyTTLMinutes) * time.Minute),
		budget:  ratelimit.NewSlidingWindowLimiter(time.Hour, cfg.TokenBudgetPerHour),
	}

	r.GET("/health", s.handleHealth)
	r.POST("/v1/chat/completions", s.authMiddleware(), s.handleChat)

	return s
}

func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.cfg.APIKey == "" {
			c.Next()
			return
		}
		auth := c.GetHeader("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if token != s.cfg.APIKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			return
		}
		c.Next()
	}
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "aegis-llm"})
}

func (s *Server) handleChat(c *gin.Context) {
	start := time.Now()

	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	fingerprint := extractFingerprint(c)
	model := req.Model
	if model == "" {
		model = s.cfg.OllamaProxyModel
	}

	// Extract last user message for pipeline analysis
	userPrompt := lastUserMessage(req.Messages)

	meta := ShieldMeta{
		Fingerprint: fingerprint,
		BudgetLimit: s.cfg.TokenBudgetPerHour,
	}

	// --- Layer 1: Penalty check ---
	if s.penalty.IsFlagged(fingerprint) {
		meta.Penalised = true
		meta.ThreatLevel = "HIGH"
		meta.BlockReason = "user in penalty box"
		slog.Warn("blocked penalised user", "fingerprint", fingerprint)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "request blocked", "aegis": meta})
		return
	}

	// --- Layer 2: Regex scan ---
	regexResult := pipeline.RunRegexScan(userPrompt)
	if regexResult.Flagged {
		s.penalty.Flag(fingerprint)
		meta.ThreatLevel = "HIGH"
		meta.BlockReason = regexResult.Reason
		slog.Warn("blocked by regex", "fingerprint", fingerprint, "reason", regexResult.Reason)
		c.JSON(http.StatusForbidden, gin.H{"error": "request blocked", "aegis": meta})
		return
	}

	// --- Layer 3: Entropy analysis ---
	entropy := pipeline.ShannonEntropy(userPrompt)
	level := pipeline.ClassifyEntropy(entropy, s.cfg.EntropyHighThreshold, s.cfg.EntropySuspiciousThreshold)
	meta.Entropy = entropy
	meta.ThreatLevel = string(level)

	if level == pipeline.EntropyHigh {
		s.penalty.Flag(fingerprint)
		meta.BlockReason = "high entropy content blocked"
		slog.Warn("blocked high entropy", "fingerprint", fingerprint, "entropy", entropy)
		c.JSON(http.StatusForbidden, gin.H{"error": "request blocked", "aegis": meta})
		return
	}

	// --- Layer 4: LLM judge for suspicious prompts ---
	if level == pipeline.EntropySuspicious {
		judgeResult, err := pipeline.RunLLMJudge(c.Request.Context(), s.ollama, s.cfg.OllamaJudgeModel, userPrompt)
		if err != nil {
			slog.Error("judge error", "err", err)
		}
		if !judgeResult.Allow {
			s.penalty.Flag(fingerprint)
			meta.ThreatLevel = "HIGH"
			meta.BlockReason = "LLM judge blocked: " + judgeResult.Reason
			slog.Warn("blocked by judge", "fingerprint", fingerprint, "reason", judgeResult.Reason)
			c.JSON(http.StatusForbidden, gin.H{"error": "request blocked", "aegis": meta})
			return
		}
	}

	// --- Layer 5: Sliding window token budget (estimated pre-check) ---
	estimatedTokens := estimateTokens(userPrompt)
	if !s.budget.Allow(fingerprint, estimatedTokens) {
		meta.ThreatLevel = "HIGH"
		meta.BlockReason = "token budget exceeded"
		meta.TokensUsed = s.budget.UsedTokens(fingerprint)
		slog.Warn("blocked budget exceeded", "fingerprint", fingerprint, "used", meta.TokensUsed)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "token budget exceeded", "aegis": meta})
		return
	}

	// --- Forward to Ollama ---
	response, err := s.ollama.ChatCompleteMessages(c.Request.Context(), model, req.Messages)
	if err != nil {
		slog.Error("ollama error", "err", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream LLM unavailable"})
		return
	}

	meta.TokensUsed = s.budget.UsedTokens(fingerprint)
	meta.ResponseTime = time.Since(start).String()

	slog.Info("request completed",
		"fingerprint", fingerprint,
		"threat_level", meta.ThreatLevel,
		"entropy", entropy,
		"tokens_used", meta.TokensUsed,
		"duration", meta.ResponseTime,
	)

	c.JSON(http.StatusOK, ChatResponse{
		Model:   model,
		Message: ollama.Message{Role: "assistant", Content: response},
		Aegis:   meta,
	})
}

func extractFingerprint(c *gin.Context) string {
	userID := strings.TrimSpace(c.GetHeader("X-User-ID"))
	ip := c.ClientIP()

	// Only trust X-Forwarded-For if set by a known proxy (Gin's ClientIP handles this)
	if userID != "" {
		return userID + "|" + ip
	}
	return "anonymous|" + ip
}

func lastUserMessage(messages []ollama.Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}

// estimateTokens is a cheap approximation: ~4 chars per token.
func estimateTokens(text string) int {
	n := len(text) / 4
	if n < 1 {
		return 1
	}
	return n
}
