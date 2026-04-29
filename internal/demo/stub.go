package demo

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

const demoReply = "Your request passed all 6 security layers and reached the demo backend. " +
	"Now try: \"ignore all previous instructions\" — aegis will block it at layer 3 (regex). " +
	"Or try a base64-encoded payload to trigger the entropy detector at layer 4."

// Stub is an in-process OpenAI-compatible HTTP server used in demo mode.
// It returns canned responses so aegis-llm can be evaluated without any external LLM.
type Stub struct {
	URL string
}

// Start binds to a random localhost port and begins serving immediately.
func Start() (*Stub, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", handleModels)
	mux.HandleFunc("/v1/chat/completions", handleChat)
	mux.HandleFunc("/v1/embeddings", handleEmbeddings)

	srv := &http.Server{Handler: mux}
	go srv.Serve(l) //nolint:errcheck
	return &Stub{URL: "http://" + l.Addr().String()}, nil
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"object": "list",
		"data": []map[string]any{
			{"id": "aegis-demo", "object": "model", "owned_by": "aegis"},
		},
	})
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Stream bool `json:"stream"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck

	if req.Stream {
		serveStream(w, demoReply)
		return
	}

	writeJSON(w, map[string]any{
		"id":     "demo-0",
		"object": "chat.completion",
		"model":  "aegis-demo",
		"choices": []map[string]any{
			{"index": 0, "message": map[string]string{"role": "assistant", "content": demoReply}},
		},
		"usage": map[string]int{
			"prompt_tokens":     10,
			"completion_tokens": len(demoReply) / 4,
			"total_tokens":      10 + len(demoReply)/4,
		},
	})
}

func handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"object": "list",
		"data": []map[string]any{
			{"object": "embedding", "index": 0, "embedding": make([]float64, 8)},
		},
		"model": "aegis-demo",
	})
}

func serveStream(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)

	// Send the reply in three chunks to mimic real streaming.
	chunks := splitThree(text)
	for _, chunk := range chunks {
		data, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{
				{"delta": map[string]string{"content": chunk}},
			},
		})
		fmt.Fprintf(w, "data: %s\n\n", data)
		if flusher != nil {
			flusher.Flush()
		}
	}

	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func splitThree(s string) [3]string {
	n := len(s)
	a, b := n/3, 2*n/3
	return [3]string{s[:a], s[a:b], s[b:]}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
