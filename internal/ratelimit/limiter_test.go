package ratelimit

import (
	"testing"
	"time"
)

func TestSlidingWindowLimiter(t *testing.T) {
	t.Run("first request within budget is allowed", func(t *testing.T) {
		l := NewSlidingWindowLimiter(time.Hour, 1000)
		if !l.Allow("alice", 100) {
			t.Error("first request should be allowed")
		}
	})

	t.Run("request that would exceed budget is denied", func(t *testing.T) {
		l := NewSlidingWindowLimiter(time.Hour, 100)
		if !l.Allow("alice", 100) {
			t.Fatal("first request should be allowed")
		}
		if l.Allow("alice", 1) {
			t.Error("request exceeding budget should be denied")
		}
	})

	t.Run("UsedTokens reflects Allow usage", func(t *testing.T) {
		l := NewSlidingWindowLimiter(time.Hour, 1000)
		l.Allow("alice", 300)
		l.Allow("alice", 200)
		if got := l.UsedTokens("alice"); got != 500 {
			t.Errorf("UsedTokens = %d, want 500", got)
		}
	})

	t.Run("Record adds to usage without checking budget", func(t *testing.T) {
		l := NewSlidingWindowLimiter(time.Hour, 100)
		l.Allow("alice", 100) // exhaust budget
		l.Record("alice", 50) // record output tokens unconditionally
		if got := l.UsedTokens("alice"); got != 150 {
			t.Errorf("UsedTokens after Record = %d, want 150", got)
		}
	})

	t.Run("usage from different fingerprints is isolated", func(t *testing.T) {
		l := NewSlidingWindowLimiter(time.Hour, 100)
		l.Allow("alice", 80)
		if !l.Allow("bob", 80) {
			t.Error("bob's budget should be independent from alice's")
		}
	})

	t.Run("entries outside the window are not counted", func(t *testing.T) {
		l := NewSlidingWindowLimiter(100*time.Millisecond, 200)
		l.Allow("alice", 150)
		time.Sleep(120 * time.Millisecond)
		// window has elapsed; the 150 tokens should no longer count
		if !l.Allow("alice", 200) {
			t.Error("request should be allowed after window expires")
		}
	})

	t.Run("UsedTokens returns 0 for unknown fingerprint", func(t *testing.T) {
		l := NewSlidingWindowLimiter(time.Hour, 1000)
		if got := l.UsedTokens("ghost"); got != 0 {
			t.Errorf("UsedTokens for unknown fingerprint = %d, want 0", got)
		}
	})
}
