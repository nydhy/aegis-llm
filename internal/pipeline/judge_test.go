package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nydhy/aegis-llm/internal/llm"
)

func fakeJudgeServer(t *testing.T, reply string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": reply}},
			},
			"usage": map[string]int{"completion_tokens": 5},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestRunLLMJudge(t *testing.T) {
	tests := []struct {
		name        string
		reply       string
		wantAllow   bool
		wantReason  string
	}{
		{
			name:      "ALLOW response",
			reply:     "ALLOW - normal cooking question",
			wantAllow: true,
		},
		{
			name:      "BLOCK response with reason",
			reply:     "BLOCK - attempts to override system instructions",
			wantAllow: false,
			wantReason: "- attempts to override system instructions",
		},
		{
			name:      "BLOCK uppercase no reason",
			reply:     "BLOCK",
			wantAllow: false,
		},
		{
			name:      "lowercase allow is permitted",
			reply:     "allow - seems fine",
			wantAllow: true,
		},
		{
			name:      "lowercase block is caught",
			reply:     "block - jailbreak attempt",
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := fakeJudgeServer(t, tt.reply)
			defer srv.Close()

			client := llm.NewClient(srv.URL, "")
			result, err := RunLLMJudge(context.Background(), client, "test-model", "some prompt")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allow != tt.wantAllow {
				t.Errorf("Allow = %v, want %v (reply: %q)", result.Allow, tt.wantAllow, tt.reply)
			}
			if tt.wantReason != "" && result.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestRunLLMJudge_FailOpen(t *testing.T) {
	// Point at a closed server — judge should fail open (allow).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	client := llm.NewClient(srv.URL, "")
	result, err := RunLLMJudge(context.Background(), client, "test-model", "some prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allow {
		t.Error("judge should fail open when upstream is unavailable")
	}
	if result.Reason != "judge unavailable" {
		t.Errorf("Reason = %q, want %q", result.Reason, "judge unavailable")
	}
}

func TestRunLLMJudge_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"overloaded"}`)
	}))
	defer srv.Close()

	client := llm.NewClient(srv.URL, "")
	result, err := RunLLMJudge(context.Background(), client, "test-model", "some prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allow {
		t.Error("judge should fail open on upstream error status")
	}
}
