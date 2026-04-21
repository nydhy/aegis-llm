package pipeline

import "math"

type EntropyLevel string

const (
	EntropyClean      EntropyLevel = "CLEAN"
	EntropySuspicious EntropyLevel = "SUSPICIOUS"
	EntropyHigh       EntropyLevel = "HIGH"
)

func ShannonEntropy(text string) float64 {
	if len(text) == 0 {
		return 0
	}

	counts := make(map[rune]int)
	total := 0
	for _, ch := range text {
		counts[ch]++
		total++
	}

	entropy := 0.0
	for _, c := range counts {
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func ClassifyEntropy(entropy, highThreshold, suspiciousThreshold float64) EntropyLevel {
	if entropy > highThreshold {
		return EntropyHigh
	}
	if entropy > suspiciousThreshold {
		return EntropySuspicious
	}
	return EntropyClean
}
