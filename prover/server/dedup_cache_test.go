package main_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
	"zolana/prover/prover/common"
	"zolana/prover/server"
)

// These tests pin the dedup contract. The hash index is authoritative and a
// miss means not cached.

func storeIndexedResult(t *testing.T, rq *server.RedisQueue, jobID, inputHash string, durationMs int64) {
	t.Helper()
	if err := rq.StoreResult(jobID, &common.ProofWithTiming{ProofDurationMs: durationMs}); err != nil {
		t.Fatalf("StoreResult: %v", err)
	}
	if err := rq.IndexResultByHash(inputHash, jobID); err != nil {
		t.Fatalf("IndexResultByHash: %v", err)
	}
}

func TestFindCachedResultReturnsAnIndexedResult(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	storeIndexedResult(t, rq, "job-cached", "hash-cached", 271)

	proof, jobID, err := rq.FindCachedResult("hash-cached")
	if err != nil {
		t.Fatalf("FindCachedResult: %v", err)
	}
	if proof == nil {
		t.Fatal("expected the indexed result to be found")
	}
	if jobID != "job-cached" {
		t.Errorf("jobID = %q, want %q", jobID, "job-cached")
	}
	if proof.ProofDurationMs != 271 {
		t.Errorf("ProofDurationMs = %d, want 271", proof.ProofDurationMs)
	}
}

// Results sitting in the queue without an index entry must not be found.
// There is no fallback scan, an unindexed result is a miss.
func TestFindCachedResultIgnoresUnindexedResults(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	const inputHash = "hash-unindexed"
	for i := 0; i < 5; i++ {
		jobID := fmt.Sprintf("unindexed-job-%d", i)
		payload, err := json.Marshal(&common.ProofWithTiming{ProofDurationMs: 100})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		err = rq.EnqueueProof("zk_results_queue", &server.ProofJob{
			ID:        jobID,
			Type:      "result",
			Payload:   json.RawMessage(payload),
			CreatedAt: time.Now(),
		})
		if err != nil {
			t.Fatalf("EnqueueProof: %v", err)
		}
		if err := rq.StoreInputHash(jobID, inputHash); err != nil {
			t.Fatalf("StoreInputHash: %v", err)
		}
	}

	proof, _, err := rq.FindCachedResult(inputHash)
	if err != nil {
		t.Fatalf("FindCachedResult: %v", err)
	}
	if proof != nil {
		t.Error("unindexed results must not be found: locating them requires " +
			"scanning the whole results queue on every miss")
	}
}

// Results carry a TTL and the index hash does not, so an entry can outlive
// what it points at. A dangling entry must not be reported as a hit.
func TestFindCachedResultDropsAStaleIndexEntry(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	const inputHash = "hash-expired"
	if err := rq.IndexResultByHash(inputHash, "job-whose-result-expired"); err != nil {
		t.Fatalf("IndexResultByHash: %v", err)
	}

	proof, _, err := rq.FindCachedResult(inputHash)
	if err != nil {
		t.Fatalf("FindCachedResult: %v", err)
	}
	if proof != nil {
		t.Error("an index entry pointing at a missing result must not be a hit")
	}

	remaining, err := rq.Client.HGet(context.Background(), server.ResultsIndexKey, inputHash).Result()
	if err == nil {
		t.Errorf("stale index entry should have been removed, still points at %q", remaining)
	}
}

func TestFindCachedFailureIgnoresUnindexedFailures(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	const inputHash = "hash-unindexed-failure"
	jobID := "unindexed-failure"
	payload, err := json.Marshal(map[string]interface{}{"error": "boom"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	err = rq.EnqueueProof("zk_failed_queue", &server.ProofJob{
		ID:        jobID + "_failed",
		Type:      "failed",
		Payload:   json.RawMessage(payload),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("EnqueueProof: %v", err)
	}
	if err := rq.StoreInputHash(jobID, inputHash); err != nil {
		t.Fatalf("StoreInputHash: %v", err)
	}

	failure, _, err := rq.FindCachedFailure(inputHash)
	if err != nil {
		t.Fatalf("FindCachedFailure: %v", err)
	}
	if failure != nil {
		t.Error("unindexed failures must not be found, for the same reason as results")
	}
}

// Transfer inputs are unique, so a miss is the common case. It must not
// touch the queues at all.
func TestFindCachedResultMissDoesNotReadTheResultsQueue(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	proof, jobID, err := rq.FindCachedResult("hash-never-seen")
	if err != nil {
		t.Fatalf("a clean miss must not error: %v", err)
	}
	if proof != nil || jobID != "" {
		t.Errorf("expected an empty miss, got proof=%v jobID=%q", proof, jobID)
	}
}
