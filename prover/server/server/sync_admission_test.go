package server

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// The whole point of the bound: a second proof waits rather than joining the
// first one on the same cores.
func TestAdmitBoundsConcurrency(t *testing.T) {
	a := newSyncAdmission(1)

	release, err := a.admit(context.Background())
	if err != nil {
		t.Fatalf("first admit: %v", err)
	}

	// A waiter with a deadline it cannot meet is shed rather than admitted.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := a.admit(ctx); err == nil {
		t.Fatal("expected the second proof to be refused while the permit is held")
	} else if err.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", err.StatusCode)
	}

	release()

	// And the permit is reusable once the first proof is done.
	release2, err := a.admit(context.Background())
	if err != nil {
		t.Fatalf("admit after release: %v", err)
	}
	release2()
}

// A caller that arrives while a permit is turning over should wait for it, not
// be shed: shedding a request the prover is about to be free for is the failure
// mode that makes clients retry for no reason.
func TestAdmitWaitsForAReleasedPermit(t *testing.T) {
	a := newSyncAdmission(1)
	release, err := a.admit(context.Background())
	if err != nil {
		t.Fatalf("first admit: %v", err)
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		release()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	second, err := a.admit(ctx)
	if err != nil {
		t.Fatalf("expected to wait for the permit, got %v", err)
	}
	second()
}

// Past the wait bound the server sheds immediately instead of parking another
// caller on a held connection.
func TestAdmitShedsBeyondTheWaitBound(t *testing.T) {
	permits := 1
	a := newSyncAdmission(permits)

	held, err := a.admit(context.Background())
	if err != nil {
		t.Fatalf("first admit: %v", err)
	}
	defer held()

	// Fill the wait queue with callers that stay parked.
	blocked := make(chan struct{})
	defer close(blocked)
	for i := 0; i < permits*syncWaitMultiple; i++ {
		go func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				<-blocked
				cancel()
			}()
			if release, err := a.admit(ctx); err == nil {
				release()
			}
		}()
	}

	// Wait for the queue to fill, then confirm the next caller is refused
	// without waiting for its own deadline.
	deadline := time.Now().Add(2 * time.Second)
	for a.waiting.Load() < int64(permits*syncWaitMultiple) {
		if time.Now().After(deadline) {
			t.Fatalf("wait queue never filled, waiting=%d", a.waiting.Load())
		}
		time.Sleep(time.Millisecond)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.admit(ctx); err == nil {
		t.Fatal("expected the overflow caller to be shed")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("shed should be immediate, took %s", elapsed)
	}
}

// Releasing twice must not conjure a permit that was never held, or the bound
// silently stops bounding.
func TestReleaseIsIdempotent(t *testing.T) {
	a := newSyncAdmission(1)
	release, err := a.admit(context.Background())
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	release()
	release()

	first, err := a.admit(context.Background())
	if err != nil {
		t.Fatalf("admit after double release: %v", err)
	}
	defer first()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := a.admit(ctx); err == nil {
		t.Fatal("a double release handed out a second permit")
	}
}
