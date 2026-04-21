package penalty

import (
	"sync"
	"time"
)

type Store struct {
	mu      sync.RWMutex
	entries map[string]time.Time // fingerprint → expiry
	ttl     time.Duration
}

func NewStore(ttl time.Duration) *Store {
	s := &Store{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
	go s.reap()
	return s
}

func (s *Store) Flag(fingerprint string) {
	s.mu.Lock()
	s.entries[fingerprint] = time.Now().Add(s.ttl)
	s.mu.Unlock()
}

func (s *Store) IsFlagged(fingerprint string) bool {
	s.mu.RLock()
	expiry, ok := s.entries[fingerprint]
	s.mu.RUnlock()
	return ok && time.Now().Before(expiry)
}

// reap removes expired entries every minute to prevent unbounded growth.
func (s *Store) reap() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for fp, expiry := range s.entries {
			if now.After(expiry) {
				delete(s.entries, fp)
			}
		}
		s.mu.Unlock()
	}
}
