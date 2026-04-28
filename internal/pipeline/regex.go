package pipeline

import (
	"regexp"
	"strings"
)

var (
	roleHijackingPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?`),
		regexp.MustCompile(`(?i)you\s+are\s+now\s+(?:an?\s+)?(?:different|new|unrestricted|jailbroken|evil|unfiltered|uncensored|dan\b)`),
		regexp.MustCompile(`(?i)act\s+as\s+(an?\s+)?(different|new|another|unrestricted)`),
		regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(\w+\s+)*(without\s+restrictions?|unrestricted|jailbreak)`),
		regexp.MustCompile(`(?i)forget\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?|training|rules?|guidelines?)`),
		regexp.MustCompile(`(?i)new\s+(system\s+)?prompt\s*:`),
	}

	instructionOverridePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)do\s+not\s+(follow|obey|comply\s+with)\s+(the\s+)?(above|previous|prior)\s+(instructions?|rules?|guidelines?)`),
		regexp.MustCompile(`(?i)override\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?)`),
		regexp.MustCompile(`(?i)disregard\s+(the\s+|all\s+|any\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)`),
		regexp.MustCompile(`(?i)bypass\s+(the\s+)?(safety|security|content)\s+(filter|check|restriction)`),
		// Special tokens used to inject system/role context across model families:
		// Llama 2: [INST], [/INST], <<SYS>>, <</SYS>>
		// Llama 3: <|start_header_id|>, <|eot_id|>
		// ChatML (Mistral/Hermes): <|im_start|>, <|im_end|>
		// GPT: <|endoftext|>
		// Alpaca: ### Human:, ### Assistant:
		regexp.MustCompile(`(?i)\[/?INST\]|\[/?SYS\]|<</?SYS>>|<<INST>>|\[SYSTEM\]`),
		regexp.MustCompile(`<\|(?:system|im_start|im_end|endoftext|eot_id|start_header_id)\|>`),
		regexp.MustCompile(`(?i)###\s*(human|assistant|system)\s*:`),
	}
)

type RegexResult struct {
	Flagged bool
	Reason  string
}

func RunRegexScan(prompt string) RegexResult {
	for _, pattern := range roleHijackingPatterns {
		if pattern.MatchString(prompt) {
			return RegexResult{Flagged: true, Reason: "role hijacking attempt"}
		}
	}
	for _, pattern := range instructionOverridePatterns {
		if pattern.MatchString(prompt) {
			return RegexResult{Flagged: true, Reason: "instruction override attempt"}
		}
	}

	// Token stuffing: repetitive content check
	words := strings.Fields(prompt)
	if len(words) > 100 {
		counts := make(map[string]int, len(words))
		for _, w := range words {
			counts[strings.ToLower(w)]++
		}
		for _, c := range counts {
			if float64(c)/float64(len(words)) > 0.4 {
				return RegexResult{Flagged: true, Reason: "token stuffing detected"}
			}
		}
	}

	return RegexResult{Flagged: false}
}
