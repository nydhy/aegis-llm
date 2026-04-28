package penalty

import (
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	t.Run("unflagged fingerprint is not blocked", func(t *testing.T) {
		s := NewStore(time.Minute)
		if s.IsFlagged("alice") {
			t.Error("new fingerprint should not be flagged")
		}
	})

	t.Run("flagged fingerprint is blocked", func(t *testing.T) {
		s := NewStore(time.Minute)
		s.Flag("alice")
		if !s.IsFlagged("alice") {
			t.Error("flagged fingerprint should be blocked")
		}
	})

	t.Run("different fingerprints are independent", func(t *testing.T) {
		s := NewStore(time.Minute)
		s.Flag("alice")
		if s.IsFlagged("bob") {
			t.Error("unflagged fingerprint should not be blocked")
		}
	})

	t.Run("penalty expires after TTL", func(t *testing.T) {
		s := NewStore(50 * time.Millisecond)
		s.Flag("alice")
		if !s.IsFlagged("alice") {
			t.Fatal("should be flagged immediately after Flag()")
		}
		time.Sleep(60 * time.Millisecond)
		if s.IsFlagged("alice") {
			t.Error("penalty should have expired after TTL")
		}
	})

	t.Run("re-flagging resets TTL", func(t *testing.T) {
		s := NewStore(100 * time.Millisecond)
		s.Flag("alice")
		time.Sleep(60 * time.Millisecond)
		s.Flag("alice") // renew
		time.Sleep(60 * time.Millisecond)
		if !s.IsFlagged("alice") {
			t.Error("penalty should still be active after re-flag")
		}
	})
}
