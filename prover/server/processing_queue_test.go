package main_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"zolana/prover/server"
)

// A worker removes its processing entry by value, because a Redis list offers
// no other handle. EnqueueProofReturning hands back exactly the bytes stored so
// that removal is one LREM.
//
// The previous implementation searched instead: LLen, then an LINDEX round trip
// per position until the job id matched, all while holding a semaphore slot.
// That is O(queue length) round trips per completed proof, and it compounds --
// on devnet at 220 workers the processing queue climbed from 210 to 751 entries
// during a single run (at most 128 proofs can be in flight), jobs waited 4.5-7s
// to be picked up, and the provers idled at 12-33% CPU proving in 0.25s.
func TestProcessingEntryIsRemovableByTheBytesItWasStoredAs(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	const queue = "zk_transfer_processing_queue"
	ctx := context.Background()

	var stored []string
	for _, id := range []string{"job-a_processing", "job-b_processing", "job-c_processing"} {
		item, err := rq.EnqueueProofReturning(queue, &server.ProofJob{
			ID:        id,
			Type:      "processing",
			Payload:   json.RawMessage(`{"test":"data"}`),
			CreatedAt: time.Now(),
		})
		if err != nil {
			t.Fatalf("EnqueueProofReturning(%s): %v", id, err)
		}
		if item == "" {
			t.Fatalf("EnqueueProofReturning(%s) returned no bytes", id)
		}
		stored = append(stored, item)
	}

	depth, err := rq.Client.LLen(ctx, queue).Result()
	if err != nil {
		t.Fatalf("LLen: %v", err)
	}
	if depth != 3 {
		t.Fatalf("processing queue depth = %d, want 3", depth)
	}

	// Removing the middle entry must take exactly that one, without touching
	// its neighbours and without reading the list to find it.
	removed, err := rq.Client.LRem(ctx, queue, 1, stored[1]).Result()
	if err != nil {
		t.Fatalf("LRem: %v", err)
	}
	if removed != 1 {
		t.Errorf("LRem removed %d entries, want 1 -- the stored bytes must match what is in the list", removed)
	}

	remaining, err := rq.Client.LRange(ctx, queue, 0, -1).Result()
	if err != nil {
		t.Fatalf("LRange: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("remaining depth = %d, want 2", len(remaining))
	}
	for _, item := range remaining {
		var job server.ProofJob
		if err := json.Unmarshal([]byte(item), &job); err != nil {
			t.Fatalf("unmarshal remaining: %v", err)
		}
		if job.ID == "job-b_processing" {
			t.Error("removed the wrong entry: job-b should be gone")
		}
	}
}

// An entry that was never stored has no bytes to match, and removal must be a
// no-op rather than an error or a scan.
func TestRemovingAnUnstoredProcessingEntryIsHarmless(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	const queue = "zk_transfer_processing_queue"
	ctx := context.Background()

	if _, err := rq.EnqueueProofReturning(queue, &server.ProofJob{
		ID:        "job-kept_processing",
		Type:      "processing",
		Payload:   json.RawMessage(`{"test":"data"}`),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("EnqueueProofReturning: %v", err)
	}

	removed, err := rq.Client.LRem(ctx, queue, 1, "not-a-stored-entry").Result()
	if err != nil {
		t.Fatalf("LRem: %v", err)
	}
	if removed != 0 {
		t.Errorf("LRem removed %d entries for a value never stored, want 0", removed)
	}

	depth, err := rq.Client.LLen(ctx, queue).Result()
	if err != nil {
		t.Fatalf("LLen: %v", err)
	}
	if depth != 1 {
		t.Errorf("processing queue depth = %d, want the stored entry untouched", depth)
	}
}
