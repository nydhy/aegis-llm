package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Client struct {
	baseURL      string
	apiKey       string
	httpClient   *http.Client
	streamClient *http.Client // no timeout; context cancellation drives lifetime
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL:      baseURL,
		apiKey:       apiKey,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		streamClient: &http.Client{},
	}
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

type chatChoice struct {
	Message Message `json:"message"`
}

type usageInfo struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Usage   usageInfo    `json:"usage"`
}

// ChatResult holds the LLM reply and token usage reported by the provider.
type ChatResult struct {
	Content          string
	CompletionTokens int
}

// Chat sends messages to any OpenAI-compatible endpoint and returns the reply with usage.
func (c *Client) Chat(ctx context.Context, model string, messages []Message) (ChatResult, error) {
	body, err := json.Marshal(chatRequest{
		Model:    model,
		Messages: messages,
		Stream:   false,
	})
	if err != nil {
		return ChatResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return ChatResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ChatResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ChatResult{}, fmt.Errorf("LLM returned status %d", resp.StatusCode)
	}

	var result chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ChatResult{}, err
	}
	if len(result.Choices) == 0 {
		return ChatResult{}, fmt.Errorf("no choices in LLM response")
	}

	return ChatResult{
		Content:          result.Choices[0].Message.Content,
		CompletionTokens: result.Usage.CompletionTokens,
	}, nil
}

// GetRaw forwards a GET request to the given path and returns the response.
// The caller must close the returned body.
func (c *Client) GetRaw(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	return c.httpClient.Do(req)
}

// PostRaw forwards a POST request with raw body to the given path and returns the response.
// The caller must close the returned body.
func (c *Client) PostRaw(ctx context.Context, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	return c.httpClient.Do(req)
}

// StreamRaw opens a streaming chat request and returns the raw SSE response body.
// The caller must close the returned reader when done.
// Context cancellation (e.g. client disconnect) terminates the stream.
func (c *Client) StreamRaw(ctx context.Context, model string, messages []Message) (io.ReadCloser, error) {
	body, err := json.Marshal(chatRequest{Model: model, Messages: messages, Stream: true})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.streamClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("LLM returned status %d", resp.StatusCode)
	}
	return resp.Body, nil
}
