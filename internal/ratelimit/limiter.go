package ratelimit

import (
	"sync"
	"time"
)

type tokenEntry struct {
	timestamp time.Time
	tokens    int
}

type userBudget struct {
	mu      sync.Mutex
	entries []tokenEntry
}

// SlidingWindowLimiter tracks token usage per user over a rolling window.
type SlidingWindowLimiter struct {
	mu          sync.RWMutex
	users       map[string]*userBudget
	window      time.Duration
	budgetLimit int
}

func NewSlidingWindowLimiter(window time.Duration, budgetLimit int) *SlidingWindowLimiter {
	l := &SlidingWindowLimiter{
		users:       make(map[string]*userBudget),
		window:      window,
		budgetLimit: budgetLimit,
	}
	go l.reap()
	return l
}

// Allow checks if the fingerprint is within budget, then records the token usage.
// Returns false if the budget would be exceeded.
func (l *SlidingWindowLimiter) Allow(fingerprint string, tokens int) bool {
	l.mu.Lock()
	ub, ok := l.users[fingerprint]
	if !ok {
		ub = &userBudget{}
		l.users[fingerprint] = ub
	}
	l.mu.Unlock()

	ub.mu.Lock()
	defer ub.mu.Unlock()

	cutoff := time.Now().Add(-l.window)

	// Drop expired entries
	valid := ub.entries[:0]
	for _, e := range ub.entries {
		if e.timestamp.After(cutoff) {
			valid = append(valid, e)
		}
	}
	ub.entries = valid

	// Sum current usage
	used := 0
	for _, e := range ub.entries {
		used += e.tokens
	}

	if used+tokens > l.budgetLimit {
		return false
	}

	ub.entries = append(ub.entries, tokenEntry{
		timestamp: time.Now(),
		tokens:    tokens,
	})
	return true
}

// UsedTokens returns the current token usage for a fingerprint within the window.
func (l *SlidingWindowLimiter) UsedTokens(fingerprint string) int {
	l.mu.RLock()
	ub, ok := l.users[fingerprint]
	l.mu.RUnlock()
	if !ok {
		return 0
	}

	cutoff := time.Now().Add(-l.window)
	ub.mu.Lock()
	defer ub.mu.Unlock()

	used := 0
	for _, e := range ub.entries {
		if e.timestamp.After(cutoff) {
			used += e.tokens
		}
	}
	return used
}

// reap removes users with no recent activity to prevent unbounded map growth.
func (l *SlidingWindowLimiter) reap() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-l.window)
		l.mu.Lock()
		for fp, ub := range l.users {
			ub.mu.Lock()
			active := false
			for _, e := range ub.entries {
				if e.timestamp.After(cutoff) {
					active = true
					break
				}
			}
			ub.mu.Unlock()
			if !active {
				delete(l.users, fp)
			}
		}
		l.mu.Unlock()
	}
}
