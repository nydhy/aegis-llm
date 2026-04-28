package pipeline

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		text string
		want float64
		eps  float64 // tolerance for float comparison
	}{
		{"empty", "", 0, 0},
		{"single char", "a", 0, 0},
		{"all same", "aaaa", 0, 0},
		{"two equal chars", "ab", 1.0, 1e-9},
		{"four equal chars", "abcd", 2.0, 1e-9},
		{"binary skewed", "aaab", 0.8113, 1e-4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShannonEntropy(tt.text)
			if math.Abs(got-tt.want) > tt.eps {
				t.Errorf("ShannonEntropy(%q) = %f, want %f", tt.text, got, tt.want)
			}
		})
	}
}

func TestClassifyEntropy(t *testing.T) {
	const high = 6.5
	const suspicious = 5.5

	tests := []struct {
		entropy float64
		want    EntropyLevel
	}{
		{0.0, EntropyClean},
		{5.0, EntropyClean},
		{5.5, EntropyClean},   // boundary: not strictly above
		{5.51, EntropySuspicious},
		{6.49, EntropySuspicious},
		{6.5, EntropySuspicious}, // boundary: not strictly above
		{6.51, EntropyHigh},
		{7.0, EntropyHigh},
	}
	for _, tt := range tests {
		got := ClassifyEntropy(tt.entropy, high, suspicious)
		if got != tt.want {
			t.Errorf("ClassifyEntropy(%v, %v, %v) = %v, want %v", tt.entropy, high, suspicious, got, tt.want)
		}
	}
}
