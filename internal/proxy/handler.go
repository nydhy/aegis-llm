package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nydhy/aegis-llm/internal/config"
	"github.com/nydhy/aegis-llm/internal/llm"
	"github.com/nydhy/aegis-llm/internal/penalty"
	"github.com/nydhy/aegis-llm/internal/pipeline"
	"github.com/nydhy/aegis-llm/internal/ratelimit"
)

type Server struct {
	router      *gin.Engine
	httpSrv     *http.Server
	cfg         *config.Config
	proxyClient *llm.Client
	judgeClient *llm.Client // nil when judge is disabled
	penalty     *penalty.Store
	rpm         *ratelimit.SlidingWindowLimiter
	budget      *ratelimit.SlidingWindowLimiter
}

type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []llm.Message `json:"messages"`
	Stream   bool          `json:"stream"`
}

type ShieldMeta struct {
	ThreatLevel  string  `json:"threat_level"`
	Entropy      float64 `json:"entropy"`
	TokensUsed   int     `json:"tokens_used_this_window"`
	BudgetLimit  int     `json:"budget_limit"`
	Penalised    bool    `json:"penalised"`
	JudgeEnabled bool    `json:"judge_enabled"`
	BlockReason  string  `json:"block_reason,omitempty"`
	ResponseTime string  `json:"response_time"`
}

type ChatResponse struct {
	Model   string        `json:"model"`
	Message llm.Message   `json:"message"`
	Aegis   ShieldMeta    `json:"aegis"`
}

func NewServer(cfg *config.Config) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	s := &Server{
		router:      r,
		cfg:         cfg,
		proxyClient: llm.NewClient(cfg.LLMBaseURL, cfg.LLMAPIKey),
		penalty:     penalty.NewStore(time.Duration(cfg.PenaltyTTLMinutes) * time.Minute),
		rpm:         ratelimit.NewSlidingWindowLimiter(time.Minute, cfg.RateLimitRPM),
		budget:      ratelimit.NewSlidingWindowLimiter(time.Hour, cfg.TokenBudgetPerHour),
	}

	if cfg.JudgeEnabled {
		s.judgeClient = llm.NewClient(cfg.JudgeBaseURL, cfg.JudgeAPIKey)
	}

	r.GET("/health", s.handleHealth)
	r.GET("/v1/models", s.authMiddleware(), s.handleModels)
	r.POST("/v1/chat/completions", s.authMiddleware(), s.handleChat)

	return s
}

func (s *Server) Run(addr string) error {
	s.httpSrv = &http.Server{Addr: addr, Handler: s.router}
	return s.httpSrv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.cfg.APIKey == "" {
			c.Next()
			return
		}
		token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token != s.cfg.APIKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			return
		}
		c.Next()
	}
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":        "ok",
		"service":       "aegis-llm",
		"judge_enabled": s.cfg.JudgeEnabled,
	})
}

func (s *Server) handleModels(c *gin.Context) {
	resp, err := s.proxyClient.GetRaw(c.Request.Context(), "/models")
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream LLM unavailable"})
		return
	}
	defer resp.Body.Close()
	c.Header("Content-Type", resp.Header.Get("Content-Type"))
	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body) //nolint:errcheck
}

const maxBodyBytes = 1 << 20 // 1 MB

func (s *Server) handleChat(c *gin.Context) {
	start := time.Now()

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	fingerprint := extractFingerprint(c)
	model := req.Model
	if model == "" {
		model = s.cfg.LLMModel
	}

	userPrompt := lastUserMessage(req.Messages)

	meta := ShieldMeta{
		BudgetLimit:  s.cfg.TokenBudgetPerHour,
		JudgeEnabled: s.cfg.JudgeEnabled,
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

	// --- Layer 2: RPM rate limit ---
	if !s.rpm.Allow(fingerprint, 1) {
		meta.ThreatLevel = "HIGH"
		meta.BlockReason = "rate limit exceeded"
		slog.Warn("blocked rate limit", "fingerprint", fingerprint)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded", "aegis": meta})
		return
	}

	// --- Layer 3: Regex scan ---
	regexResult := pipeline.RunRegexScan(userPrompt)
	if regexResult.Flagged {
		s.penalty.Flag(fingerprint)
		meta.ThreatLevel = "HIGH"
		meta.BlockReason = regexResult.Reason
		slog.Warn("blocked by regex", "fingerprint", fingerprint, "reason", regexResult.Reason)
		c.JSON(http.StatusForbidden, gin.H{"error": "request blocked", "aegis": meta})
		return
	}

	// --- Layer 4: Entropy analysis ---
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

	// --- Layer 5: LLM judge (only if enabled and prompt is suspicious) ---
	if level == pipeline.EntropySuspicious && s.judgeClient != nil {
		judgeResult, _ := pipeline.RunLLMJudge(c.Request.Context(), s.judgeClient, s.cfg.JudgeModel, userPrompt)
		if !judgeResult.Allow {
			s.penalty.Flag(fingerprint)
			meta.ThreatLevel = "HIGH"
			meta.BlockReason = "LLM judge: " + judgeResult.Reason
			slog.Warn("blocked by judge", "fingerprint", fingerprint, "reason", judgeResult.Reason)
			c.JSON(http.StatusForbidden, gin.H{"error": "request blocked", "aegis": meta})
			return
		}
	}

	// --- Layer 6: Sliding window token budget ---
	estimatedTokens := estimateTokens(userPrompt)
	if !s.budget.Allow(fingerprint, estimatedTokens) {
		meta.ThreatLevel = "HIGH"
		meta.BlockReason = "token budget exceeded"
		meta.TokensUsed = s.budget.UsedTokens(fingerprint)
		slog.Warn("blocked budget exceeded", "fingerprint", fingerprint, "used", meta.TokensUsed)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "token budget exceeded", "aegis": meta})
		return
	}

	// --- Forward to LLM ---
	if req.Stream {
		s.handleChatStream(c, fingerprint, model, entropy, req.Messages, meta, start)
		return
	}

	result, err := s.proxyClient.Chat(c.Request.Context(), model, req.Messages)
	if err != nil {
		slog.Error("upstream LLM error", "err", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream LLM unavailable"})
		return
	}

	// Record actual output tokens against the budget.
	// If the provider returns usage data we use it; otherwise fall back to estimation.
	outputTokens := result.CompletionTokens
	if outputTokens == 0 {
		outputTokens = estimateTokens(result.Content)
	}
	s.budget.Record(fingerprint, outputTokens)

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
		Message: llm.Message{Role: "assistant", Content: result.Content},
		Aegis:   meta,
	})
}

// streamChunk is the minimal shape of an OpenAI SSE chunk we need to parse.
type streamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

func (s *Server) handleChatStream(
	c *gin.Context,
	fingerprint, model string,
	entropy float64,
	messages []llm.Message,
	meta ShieldMeta,
	start time.Time,
) {
	body, err := s.proxyClient.StreamRaw(c.Request.Context(), model, messages)
	if err != nil {
		slog.Error("upstream LLM stream error", "err", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream LLM unavailable"})
		return
	}
	defer body.Close()

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	flusher, canFlush := c.Writer.(http.Flusher)
	reader := bufio.NewReader(body)
	var content strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			fmt.Fprint(c.Writer, line)
			if canFlush {
				flusher.Flush()
			}
			trimmed := strings.TrimRight(line, "\r\n")
			if data, ok := strings.CutPrefix(trimmed, "data: "); ok && data != "[DONE]" {
				var chunk streamChunk
				if json.Unmarshal([]byte(data), &chunk) == nil && len(chunk.Choices) > 0 {
					content.WriteString(chunk.Choices[0].Delta.Content)
				}
			}
		}
		if err != nil {
			break
		}
	}

	s.budget.Record(fingerprint, estimateTokens(content.String()))

	slog.Info("stream completed",
		"fingerprint", fingerprint,
		"threat_level", meta.ThreatLevel,
		"entropy", entropy,
		"tokens_estimated", estimateTokens(content.String()),
		"duration", time.Since(start),
	)
}

func extractFingerprint(c *gin.Context) string {
	userID := strings.TrimSpace(c.GetHeader("X-User-ID"))
	ip := c.ClientIP()
	if userID != "" {
		return userID + "|" + ip
	}
	return "anonymous|" + ip
}

func lastUserMessage(messages []llm.Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}

// estimateTokens approximates token count at ~4 chars per token.
func estimateTokens(text string) int {
	if n := len(text) / 4; n > 0 {
		return n
	}
	return 1
}
