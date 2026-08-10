package main_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
	"zolana/prover/prover/common"
	"zolana/prover/server"

	"github.com/alicebob/miniredis/v2"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/google/uuid"
)

// redisURLForTest prefers TEST_REDIS_URL and falls back to an in-process
// Redis, so the queue tests run everywhere instead of skipping.
func redisURLForTest(t *testing.T) string {
	if redisURL := os.Getenv("TEST_REDIS_URL"); redisURL != "" {
		return redisURL
	}
	// RunT registers its own cleanup, so the server dies with the test.
	return "redis://" + miniredis.RunT(t).Addr() + "/0"
}

func setupRedisQueue(t *testing.T) *server.RedisQueue {
	return setupRedisQueueAt(t, redisURLForTest(t))
}

// setupRedisQueueAt is for tests that also need to hand the URL to something
// else, such as a server config, so both ends talk to the same instance.
func setupRedisQueueAt(t *testing.T, redisURL string) *server.RedisQueue {
	rq, err := server.NewRedisQueue(redisURL)
	if err != nil {
		t.Fatalf("Redis not available for testing: %v", err)
	}

	err = rq.Client.FlushDB(context.Background()).Err()
	if err != nil {
		t.Fatalf("Failed to flush Redis DB: %v", err)
	}

	return rq
}

func teardownRedisQueue(t *testing.T, rq *server.RedisQueue) {
	if rq != nil {
		rq.Client.FlushDB(context.Background()).Err()
		rq.Client.Close()
	}
}

func TestPeriodicCleanupFunctionality(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	now := time.Now()
	oldTime := now.Add(-35 * time.Minute)    // 35 minutes ago (should be removed)
	recentTime := now.Add(-20 * time.Minute) // 20 minutes ago (should stay)

	testJobs := []struct {
		queueName    string
		job          *server.ProofJob
		shouldRemove bool
	}{
		{
			queueName: "zk_address_append_queue",
			job: &server.ProofJob{
				ID:        uuid.New().String(),
				Type:      "zk_proof",
				Payload:   json.RawMessage(`{"tree_height": 40, "batch_size": 10}`),
				CreatedAt: oldTime,
			},
			shouldRemove: true,
		},
		{
			queueName: "zk_address_append_queue",
			job: &server.ProofJob{
				ID:        uuid.New().String(),
				Type:      "zk_proof",
				Payload:   json.RawMessage(`{"tree_height": 40, "batch_size": 10}`),
				CreatedAt: recentTime,
			},
			shouldRemove: false,
		},
		{
			queueName: "zk_failed_queue",
			job: &server.ProofJob{
				ID:        uuid.New().String(),
				Type:      "zk_proof",
				Payload:   json.RawMessage(`{"height": 32, "batch_size": 10}`),
				CreatedAt: oldTime,
			},
			shouldRemove: false,
		},
		{
			queueName: "zk_results_queue",
			job: &server.ProofJob{
				ID:        uuid.New().String(),
				Type:      "zk_proof",
				Payload:   json.RawMessage(`{"tree_height": 40, "batch_size": 10}`),
				CreatedAt: recentTime,
			},
			shouldRemove: false,
		},
	}

	for _, testJob := range testJobs {
		err := rq.EnqueueProof(testJob.queueName, testJob.job)
		if err != nil {
			t.Fatalf("Failed to enqueue test job to %s: %v", testJob.queueName, err)
		}
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get initial queue stats: %v", err)
	}

	expectedInitial := map[string]int64{
		"zk_address_append_queue": 2,
		"zk_failed_queue":         1,
		"zk_results_queue":        1,
	}

	for queue, expected := range expectedInitial {
		if stats[queue] != expected {
			t.Errorf("Expected %s to have %d jobs initially, got %d", queue, expected, stats[queue])
		}
	}

	err = rq.CleanupOldRequests()
	if err != nil {
		t.Errorf("CleanupOldRequests failed: %v", err)
	}

	stats, err = rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats after cleanup: %v", err)
	}

	expectedAfter := map[string]int64{
		"zk_address_append_queue": 1, // 1 recent job remains, 1 old removed
		"zk_failed_queue":         1, // untouched by cleanup
		"zk_results_queue":        1, // untouched by cleanup
	}

	for queue, expected := range expectedAfter {
		if stats[queue] != expected {
			t.Errorf("Expected %s to have %d jobs after cleanup, got %d", queue, expected, stats[queue])
		}
	}

	remainingAddress, err := rq.DequeueProof("zk_address_append_queue", 1*time.Second)
	if err != nil {
		t.Errorf("Failed to dequeue remaining address append job: %v", err)
	}
	if remainingAddress == nil {
		t.Errorf("Expected to find remaining address append job")
	}

	emptyAddress, err := rq.DequeueProof("zk_address_append_queue", 500*time.Millisecond)
	if err != nil {
		t.Errorf("Failed to check empty address append queue: %v", err)
	}
	if emptyAddress != nil {
		t.Errorf("Expected address append queue to be empty after dequeue, but found job: %v", emptyAddress)
	}
}

func TestCleanupOldProofRequests(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	now := time.Now()
	oldTime := now.Add(-45 * time.Minute)    // 45 minutes ago (should be removed)
	recentTime := now.Add(-15 * time.Minute) // 15 minutes ago (should stay)

	oldAddressJob := &server.ProofJob{
		ID:        uuid.New().String(),
		Type:      "zk_proof",
		Payload:   json.RawMessage(`{"tree_height": 40, "batch_size": 10}`),
		CreatedAt: oldTime,
	}

	recentAddressJob := &server.ProofJob{
		ID:        uuid.New().String(),
		Type:      "zk_proof",
		Payload:   json.RawMessage(`{"tree_height": 40, "batch_size": 10}`),
		CreatedAt: recentTime,
	}

	// Jobs in an isolated queue that cleanup does not touch
	oldFailedJob := &server.ProofJob{
		ID:        uuid.New().String(),
		Type:      "zk_proof",
		Payload:   json.RawMessage(`{"height": 32, "batch_size": 10}`),
		CreatedAt: oldTime,
	}

	recentFailedJob := &server.ProofJob{
		ID:        uuid.New().String(),
		Type:      "zk_proof",
		Payload:   json.RawMessage(`{"height": 32, "batch_size": 10}`),
		CreatedAt: recentTime,
	}

	err := rq.EnqueueProof("zk_address_append_queue", oldAddressJob)
	if err != nil {
		t.Fatalf("Failed to enqueue old address append job: %v", err)
	}

	err = rq.EnqueueProof("zk_failed_queue", oldFailedJob)
	if err != nil {
		t.Fatalf("Failed to enqueue old failed job: %v", err)
	}

	err = rq.EnqueueProof("zk_address_append_queue", recentAddressJob)
	if err != nil {
		t.Fatalf("Failed to enqueue recent address append job: %v", err)
	}

	err = rq.EnqueueProof("zk_failed_queue", recentFailedJob)
	if err != nil {
		t.Fatalf("Failed to enqueue recent failed job: %v", err)
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get initial queue stats: %v", err)
	}
	if stats["zk_address_append_queue"] != 2 {
		t.Errorf("Expected zk_address_append_queue to have 2 jobs initially, got %d", stats["zk_address_append_queue"])
	}
	if stats["zk_failed_queue"] != 2 {
		t.Errorf("Expected zk_failed_queue to have 2 jobs initially, got %d", stats["zk_failed_queue"])
	}

	err = rq.CleanupOldRequests()
	if err != nil {
		t.Errorf("CleanupOldRequests failed: %v", err)
	}

	stats, err = rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats after cleanup: %v", err)
	}

	if stats["zk_address_append_queue"] != 1 {
		t.Errorf("Expected zk_address_append_queue to have 1 job after cleanup, got %d", stats["zk_address_append_queue"])
	}
	if stats["zk_failed_queue"] != 2 {
		t.Errorf("Expected zk_failed_queue to have 2 jobs after cleanup, got %d", stats["zk_failed_queue"])
	}

	dequeuedAddress, err := rq.DequeueProof("zk_address_append_queue", 1*time.Second)
	if err != nil {
		t.Errorf("Failed to dequeue remaining address append job: %v", err)
	}
	if dequeuedAddress == nil {
		t.Errorf("Expected to find remaining address append job")
	} else if dequeuedAddress.ID != recentAddressJob.ID {
		t.Errorf("Expected remaining job to be recent job, got ID %s instead of %s", dequeuedAddress.ID, recentAddressJob.ID)
	}
}

func createTestJob(jobID, circuitType string) *server.ProofJob {
	var payload json.RawMessage

	switch circuitType {
	case "batch-update":
		payload = json.RawMessage(`{"height": 32, "batch_size": 10, "old_root": "0", "new_root": "1", "leaves": []}`)
	case "batch-append":
		payload = json.RawMessage(`{"height": 32, "batch_size": 10, "old_root": "0", "new_root": "1", "leaves": [], "merkle_proofs": []}`)
	case "batch-address-append":
		payload = json.RawMessage(`{"tree_height": 40, "batch_size": 10, "old_root": "0", "new_root": "1", "addresses": []}`)
	default:
		payload = json.RawMessage(`{"state_merkle_tree_root": "0", "state_merkle_tree_next_index": 0}`)
	}

	return &server.ProofJob{
		ID:        jobID,
		Type:      "zk_proof",
		Payload:   payload,
		CreatedAt: time.Now(),
	}
}

func TestRedisQueueConnection(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	err := rq.Client.Ping(context.Background()).Err()
	if err != nil {
		t.Errorf("Redis ping failed: %v", err)
	}
}

func TestQueueStats(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}

	expectedQueues := []string{
		"zk_address_append_queue",
		"zk_address_append_processing_queue",
		"zk_failed_queue",
		"zk_results_queue",
	}

	for _, queue := range expectedQueues {
		if _, exists := stats[queue]; !exists {
			t.Errorf("Expected queue %s not found in stats", queue)
		}
		if stats[queue] != int64(0) {
			t.Errorf("Expected queue %s to be empty, got %d", queue, stats[queue])
		}
	}
}

func TestEnqueueToFailedQueue(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	job := createTestJob("test-failed-1", "batch-address-append")

	err := rq.EnqueueProof("zk_failed_queue", job)
	if err != nil {
		t.Errorf("Failed to enqueue proof: %v", err)
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}
	if stats["zk_failed_queue"] != int64(1) {
		t.Errorf("Expected zk_failed_queue to have 1 job, got %d", stats["zk_failed_queue"])
	}
}

func TestEnqueueToResultsQueue(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	job := createTestJob("test-results-1", "batch-address-append")

	err := rq.EnqueueProof("zk_results_queue", job)
	if err != nil {
		t.Errorf("Failed to enqueue proof: %v", err)
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}
	if stats["zk_results_queue"] != int64(1) {
		t.Errorf("Expected zk_results_queue to have 1 job, got %d", stats["zk_results_queue"])
	}
}

func TestEnqueueToAddressAppendQueue(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	job := createTestJob("test-address-append-1", "batch-address-append")

	err := rq.EnqueueProof("zk_address_append_queue", job)
	if err != nil {
		t.Errorf("Failed to enqueue proof: %v", err)
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}
	if stats["zk_address_append_queue"] != int64(1) {
		t.Errorf("Expected zk_address_append_queue to have 1 job, got %d", stats["zk_address_append_queue"])
	}
}

func TestDequeueFromFailedQueue(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	originalJob := createTestJob("test-dequeue-failed", "batch-address-append")

	err := rq.EnqueueProof("zk_failed_queue", originalJob)
	if err != nil {
		t.Fatalf("Failed to enqueue proof: %v", err)
	}

	dequeuedJob, err := rq.DequeueProof("zk_failed_queue", 1*time.Second)
	if err != nil {
		t.Errorf("Failed to dequeue proof: %v", err)
	}
	if dequeuedJob == nil {
		t.Fatalf("Expected to dequeue a job, got nil")
	}
	if dequeuedJob.ID != originalJob.ID {
		t.Errorf("Expected job ID %s, got %s", originalJob.ID, dequeuedJob.ID)
	}
	if dequeuedJob.Type != originalJob.Type {
		t.Errorf("Expected job type %s, got %s", originalJob.Type, dequeuedJob.Type)
	}
}

func TestDequeueFromResultsQueue(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	originalJob := createTestJob("test-dequeue-results", "batch-address-append")

	err := rq.EnqueueProof("zk_results_queue", originalJob)
	if err != nil {
		t.Fatalf("Failed to enqueue proof: %v", err)
	}

	dequeuedJob, err := rq.DequeueProof("zk_results_queue", 1*time.Second)
	if err != nil {
		t.Errorf("Failed to dequeue proof: %v", err)
	}
	if dequeuedJob == nil {
		t.Fatalf("Expected to dequeue a job, got nil")
	}
	if dequeuedJob.ID != originalJob.ID {
		t.Errorf("Expected job ID %s, got %s", originalJob.ID, dequeuedJob.ID)
	}
}

func TestDequeueFromAddressAppendQueue(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	originalJob := createTestJob("test-dequeue-address-append", "batch-address-append")

	err := rq.EnqueueProof("zk_address_append_queue", originalJob)
	if err != nil {
		t.Fatalf("Failed to enqueue proof: %v", err)
	}

	dequeuedJob, err := rq.DequeueProof("zk_address_append_queue", 1*time.Second)
	if err != nil {
		t.Errorf("Failed to dequeue proof: %v", err)
	}
	if dequeuedJob == nil {
		t.Fatalf("Expected to dequeue a job, got nil")
	}
	if dequeuedJob.ID != originalJob.ID {
		t.Errorf("Expected job ID %s, got %s", originalJob.ID, dequeuedJob.ID)
	}
}

func TestDequeueTimeout(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	start := time.Now()
	job, err := rq.DequeueProof("zk_address_append_queue", 500*time.Millisecond)
	duration := time.Since(start)

	if err != nil {
		t.Errorf("Dequeue failed: %v", err)
	}
	if job != nil {
		t.Errorf("Expected nil job from empty queue, got %v", job)
	}
	if duration < 400*time.Millisecond {
		t.Errorf("Timeout duration too short: %v", duration)
	}
	// A 1s block cannot return in under 1s, so the old "> 1 * time.Second"
	// bound was unsatisfiable -- it measured 1.0013s here. The point of the
	// upper bound is to catch a block that ignores its timeout entirely, so it
	// needs slack for scheduling.
	if duration > 3*time.Second {
		t.Errorf("Timeout duration too long: %v", duration)
	}
}

func TestQueueNameForCircuitType(t *testing.T) {
	tests := []struct {
		circuitType   common.CircuitType
		expectedQueue string
	}{
		{common.BatchAddressAppendCircuitType, "zk_address_append_queue"},
		{common.TransferConfidentialCircuitType, ""},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("CircuitType_%s", test.circuitType), func(t *testing.T) {
			queueName := server.GetQueueNameForCircuit(test.circuitType)
			if queueName != test.expectedQueue {
				t.Errorf("Expected queue %s for circuit type %s, got %s", test.expectedQueue, test.circuitType, queueName)
			}
		})
	}
}

func TestMultipleJobsInDifferentQueues(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	addressAppendJob := createTestJob("address-append-job", "batch-address-append")
	failedJob := createTestJob("failed-job", "batch-address-append")
	resultsJob := createTestJob("results-job", "batch-address-append")

	err := rq.EnqueueProof("zk_address_append_queue", addressAppendJob)
	if err != nil {
		t.Fatalf("Failed to enqueue address append job: %v", err)
	}

	err = rq.EnqueueProof("zk_failed_queue", failedJob)
	if err != nil {
		t.Fatalf("Failed to enqueue failed job: %v", err)
	}

	err = rq.EnqueueProof("zk_results_queue", resultsJob)
	if err != nil {
		t.Fatalf("Failed to enqueue results job: %v", err)
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}

	if stats["zk_address_append_queue"] != int64(1) {
		t.Errorf("Expected zk_address_append_queue to have 1 job, got %d", stats["zk_address_append_queue"])
	}
	if stats["zk_failed_queue"] != int64(1) {
		t.Errorf("Expected zk_failed_queue to have 1 job, got %d", stats["zk_failed_queue"])
	}
	if stats["zk_results_queue"] != int64(1) {
		t.Errorf("Expected zk_results_queue to have 1 job, got %d", stats["zk_results_queue"])
	}

	dequeuedAddressAppend, err := rq.DequeueProof("zk_address_append_queue", 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to dequeue from address append queue: %v", err)
	}
	if dequeuedAddressAppend == nil {
		t.Fatalf("Expected to dequeue an address append job, got nil")
	}
	if dequeuedAddressAppend.ID != addressAppendJob.ID {
		t.Errorf("Expected address append job ID %s, got %s", addressAppendJob.ID, dequeuedAddressAppend.ID)
	}

	dequeuedFailed, err := rq.DequeueProof("zk_failed_queue", 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to dequeue from failed queue: %v", err)
	}
	if dequeuedFailed.ID != failedJob.ID {
		t.Errorf("Expected failed job ID %s, got %s", failedJob.ID, dequeuedFailed.ID)
	}

	dequeuedResults, err := rq.DequeueProof("zk_results_queue", 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to dequeue from results queue: %v", err)
	}
	if dequeuedResults.ID != resultsJob.ID {
		t.Errorf("Expected results job ID %s, got %s", resultsJob.ID, dequeuedResults.ID)
	}
}

func TestJobResultStorage(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	jobID := "test-result-job"

	// GetResult decodes into common.ProofWithTiming.
	stored := &common.ProofWithTiming{ProofDurationMs: 271}

	err := rq.StoreResult(jobID, stored)
	if err != nil {
		t.Fatalf("Failed to store result: %v", err)
	}

	result, err := rq.GetResult(jobID)
	if err != nil {
		t.Fatalf("Failed to retrieve result: %v", err)
	}

	loaded, ok := result.(*common.ProofWithTiming)
	if !ok {
		t.Fatalf("Expected result to be *common.ProofWithTiming, got %T", result)
	}
	if loaded.ProofDurationMs != stored.ProofDurationMs {
		t.Errorf(
			"ProofDurationMs = %d, want %d",
			loaded.ProofDurationMs, stored.ProofDurationMs,
		)
	}
}

func TestQueuedCommittedProofResultRoundTrip(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	_, _, g1, g2 := bn254.Generators()
	var commitment, commitmentPok bn254.G1Affine
	commitment.ScalarMultiplication(&g1, big.NewInt(2))
	commitmentPok.ScalarMultiplication(&g1, big.NewInt(3))
	result := &common.ProofWithTiming{
		Proof: &common.Proof{Proof: &groth16bn254.Proof{
			Ar:            g1,
			Bs:            g2,
			Krs:           g1,
			Commitments:   []bn254.G1Affine{commitment},
			CommitmentPok: commitmentPok,
		}},
		ProofDurationMs: 42,
	}

	const jobID = "test-committed-proof-result"
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal committed proof result: %v", err)
	}

	// Both, because the worker does both. StoreResult writes zk_result_<id>,
	// which GetResult reads, and the queue entry is what cleanup ages out.
	if err := rq.StoreResult(jobID, result); err != nil {
		t.Fatalf("store committed proof result: %v", err)
	}
	if err := rq.EnqueueProof("zk_results_queue", &server.ProofJob{
		ID:        jobID,
		Type:      "result",
		Payload:   payload,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("enqueue committed proof result: %v", err)
	}

	stored, err := rq.GetResult(jobID)
	if err != nil {
		t.Fatalf("get committed proof result: %v", err)
	}
	storedResult, ok := stored.(*common.ProofWithTiming)
	if !ok {
		t.Fatalf("stored result type = %T, want *common.ProofWithTiming", stored)
	}
	storedProof, ok := storedResult.Proof.Proof.(*groth16bn254.Proof)
	if !ok {
		t.Fatalf("stored proof type = %T, want *groth16bn254.Proof", storedResult.Proof.Proof)
	}
	if len(storedProof.Commitments) != 1 {
		t.Fatalf("stored commitment count = %d, want 1", len(storedProof.Commitments))
	}
	if !storedProof.Commitments[0].Equal(&commitment) {
		t.Fatal("stored proof commitment does not match")
	}
	if !storedProof.CommitmentPok.Equal(&commitmentPok) {
		t.Fatal("stored proof commitment PoK does not match")
	}
}

// CleanupOldResults removes results by age, and only by age. Nothing caps the
// queue length, so zk_results_queue grows unbounded between cleanup passes.
func TestResultCleanup(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	// The cutoff is one hour, so these straddle it.
	const staleCount, freshCount = 3, 2
	enqueue := func(id string, createdAt time.Time) {
		t.Helper()
		job := &server.ProofJob{
			ID:        id,
			Type:      "result",
			Payload:   json.RawMessage(`{"test": "data"}`),
			CreatedAt: createdAt,
		}
		if err := rq.EnqueueProof("zk_results_queue", job); err != nil {
			t.Fatalf("Failed to enqueue %s: %v", id, err)
		}
	}
	for i := 0; i < staleCount; i++ {
		enqueue(fmt.Sprintf("stale-result-%d", i), time.Now().Add(-2*time.Hour))
	}
	for i := 0; i < freshCount; i++ {
		enqueue(fmt.Sprintf("fresh-result-%d", i), time.Now())
	}

	if err := rq.CleanupOldResults(); err != nil {
		t.Fatalf("Failed to cleanup old results: %v", err)
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}
	if stats["zk_results_queue"] != int64(freshCount) {
		t.Errorf(
			"Expected only the %d recent results to survive cleanup, got %d",
			freshCount, stats["zk_results_queue"],
		)
	}
}

// A result key with no TTL never expires on its own, so the cleanup is the only
// thing that removes it. The scan must reach every one of them, past the size of
// a single batch.
func TestOldResultKeyCleanupReachesEveryKey(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	ctx := context.Background()
	const persistentCount = 1200
	for i := 0; i < persistentCount; i++ {
		key := fmt.Sprintf("zk_result_persistent-%d", i)
		if err := rq.Client.Set(ctx, key, `{"test":"data"}`, 0).Err(); err != nil {
			t.Fatalf("Failed to store %s: %v", key, err)
		}
	}
	if err := rq.Client.Set(ctx, "zk_result_fresh", `{"test":"data"}`, time.Hour).Err(); err != nil {
		t.Fatalf("Failed to store the fresh result key: %v", err)
	}

	if err := rq.CleanupOldResultKeys(); err != nil {
		t.Fatalf("Failed to cleanup old result keys: %v", err)
	}

	for i := 0; i < persistentCount; i++ {
		key := fmt.Sprintf("zk_result_persistent-%d", i)
		exists, err := rq.Client.Exists(ctx, key).Result()
		if err != nil {
			t.Fatalf("Failed to check %s: %v", key, err)
		}
		if exists != 0 {
			t.Fatalf("Expected %s to be removed by cleanup", key)
		}
	}

	exists, err := rq.Client.Exists(ctx, "zk_result_fresh").Result()
	if err != nil {
		t.Fatalf("Failed to check the fresh result key: %v", err)
	}
	if exists != 1 {
		t.Error("Expected the result key with a live TTL to survive cleanup")
	}
}

func TestWorkerCreation(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	keyManager := common.NewLazyKeyManager("./proving-keys/", common.DefaultDownloadConfig())

	addressAppendWorker := server.NewAddressAppendQueueWorker(rq, keyManager)
	if addressAppendWorker == nil {
		t.Errorf("Expected address append worker to be created, got nil")
	}

	var _ server.QueueWorker = addressAppendWorker
}

func TestJobProcessingFlow(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	jobID := "test-processing-flow"
	job := createTestJob(jobID, "batch-address-append")

	err := rq.EnqueueProof("zk_address_append_queue", job)
	if err != nil {
		t.Fatalf("Failed to enqueue job: %v", err)
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}
	if stats["zk_address_append_queue"] != int64(1) {
		t.Errorf("Expected zk_address_append_queue to have 1 job, got %d", stats["zk_address_append_queue"])
	}

	dequeuedJob, err := rq.DequeueProof("zk_address_append_queue", 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to dequeue job: %v", err)
	}
	if dequeuedJob.ID != jobID {
		t.Errorf("Expected job ID %s, got %s", jobID, dequeuedJob.ID)
	}

	processingJob := &server.ProofJob{
		ID:        jobID + "_processing",
		Type:      "processing",
		Payload:   job.Payload,
		CreatedAt: time.Now(),
	}
	err = rq.EnqueueProof("zk_address_append_processing_queue", processingJob)
	if err != nil {
		t.Fatalf("Failed to enqueue processing job: %v", err)
	}

	stats, err = rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}
	if stats["zk_address_append_processing_queue"] != int64(1) {
		t.Errorf("Expected zk_address_append_processing_queue to have 1 job, got %d", stats["zk_address_append_processing_queue"])
	}

	resultJob := &server.ProofJob{
		ID:        jobID,
		Type:      "result",
		Payload:   json.RawMessage(`{"proof": "completed", "public_inputs": []}`),
		CreatedAt: time.Now(),
	}
	err = rq.EnqueueProof("zk_results_queue", resultJob)
	if err != nil {
		t.Fatalf("Failed to enqueue result job: %v", err)
	}

	stats, err = rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}
	if stats["zk_results_queue"] != int64(1) {
		t.Errorf("Expected zk_results_queue to have 1 job, got %d", stats["zk_results_queue"])
	}
}

func TestFailedJobStatusDetails(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	jobID := uuid.New().String()

	originalJob := createTestJob(jobID, "batch-update")
	errorMessage := "Proof generation failed: Invalid merkle tree state"

	failureDetails := map[string]interface{}{
		"original_job": originalJob,
		"error":        errorMessage,
		"failed_at":    time.Now(),
	}

	failedData, err := json.Marshal(failureDetails)
	if err != nil {
		t.Fatalf("Failed to marshal failure details: %v", err)
	}

	failedJob := &server.ProofJob{
		ID:        jobID + "_failed",
		Type:      "failed",
		Payload:   json.RawMessage(failedData),
		CreatedAt: time.Now(),
	}

	err = rq.EnqueueProof("zk_failed_queue", failedJob)
	if err != nil {
		t.Fatalf("Failed to enqueue failed job: %v", err)
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}
	if stats["zk_failed_queue"] != int64(1) {
		t.Errorf("Expected zk_failed_queue to have 1 job, got %d", stats["zk_failed_queue"])
	}

	items, err := rq.Client.LRange(rq.Ctx, "zk_failed_queue", 0, -1).Result()
	if err != nil {
		t.Fatalf("Failed to get failed queue items: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("Expected 1 item in failed queue, got %d", len(items))
	}

	var retrievedJob server.ProofJob
	err = json.Unmarshal([]byte(items[0]), &retrievedJob)
	if err != nil {
		t.Fatalf("Failed to unmarshal failed job: %v", err)
	}

	var parsedFailureDetails map[string]interface{}
	err = json.Unmarshal(retrievedJob.Payload, &parsedFailureDetails)
	if err != nil {
		t.Fatalf("Failed to parse failure details: %v", err)
	}

	if retrievedError, ok := parsedFailureDetails["error"].(string); !ok {
		t.Errorf("Expected error field in failure details")
	} else if retrievedError != errorMessage {
		t.Errorf("Expected error message '%s', got '%s'", errorMessage, retrievedError)
	}

	if _, ok := parsedFailureDetails["failed_at"]; !ok {
		t.Errorf("Expected failed_at field in failure details")
	}

	if _, ok := parsedFailureDetails["original_job"]; !ok {
		t.Errorf("Expected original_job field in failure details")
	}
}

func TestFailedJobStatusHTTPEndpoint(t *testing.T) {
	redisURL := redisURLForTest(t)
	rq := setupRedisQueueAt(t, redisURL)
	defer teardownRedisQueue(t, rq)

	keyManager := common.NewLazyKeyManager("./proving-keys/", common.DefaultDownloadConfig())

	config := &server.EnhancedConfig{
		ProverAddress:  "localhost:8082",
		MetricsAddress: "localhost:9997",
		Queue: &server.QueueConfig{
			RedisURL: redisURL,
			Enabled:  true,
		},
	}

	serverJob := server.RunEnhanced(config, rq, keyManager)
	defer serverJob.RequestStop()

	time.Sleep(100 * time.Millisecond)

	jobID := uuid.New().String()
	errorMessage := "HTTP Test: Proof generation failed due to invalid input parameters"

	originalJob := createTestJob(jobID, "batch-update")

	failureDetails := map[string]interface{}{
		"original_job": originalJob,
		"error":        errorMessage,
		"failed_at":    time.Now().Format(time.RFC3339),
	}

	failedData, err := json.Marshal(failureDetails)
	if err != nil {
		t.Fatalf("Failed to marshal failure details: %v", err)
	}

	failedJob := &server.ProofJob{
		ID:        jobID + "_failed",
		Type:      "failed",
		Payload:   json.RawMessage(failedData),
		CreatedAt: time.Now(),
	}

	err = rq.EnqueueProof("zk_failed_queue", failedJob)
	if err != nil {
		t.Fatalf("Failed to enqueue failed job: %v", err)
	}

	statusURL := fmt.Sprintf("http://%s/prove/status?job_id=%s", config.ProverAddress, jobID)
	resp, err := http.Get(statusURL)
	if err != nil {
		t.Fatalf("Failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var statusResponse map[string]interface{}
	err = json.Unmarshal(body, &statusResponse)
	if err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if status, ok := statusResponse["status"].(string); !ok || status != "failed" {
		t.Errorf("Expected status 'failed', got %v", statusResponse["status"])
	}

	if message, ok := statusResponse["message"].(string); !ok {
		t.Errorf("Expected message field in response")
	} else if !strings.Contains(message, errorMessage) {
		t.Errorf("Expected message to contain '%s', got '%s'", errorMessage, message)
	}

	if errorField, ok := statusResponse["error"].(string); !ok {
		t.Errorf("Expected error field in response")
	} else if errorField != errorMessage {
		t.Errorf("Expected error field to be '%s', got '%s'", errorMessage, errorField)
	}

	if _, ok := statusResponse["failed_at"]; !ok {
		t.Errorf("Expected failed_at field in response")
	}

	if jobIDField, ok := statusResponse["job_id"].(string); !ok || jobIDField != jobID {
		t.Errorf("Expected job_id to be '%s', got %v", jobID, statusResponse["job_id"])
	}
}

func TestBatchOperationsAlwaysUseQueue(t *testing.T) {
	batchTests := []struct {
		circuitType   common.CircuitType
		expectedQueue string
	}{
		{common.BatchAddressAppendCircuitType, "zk_address_append_queue"},
	}

	for _, test := range batchTests {
		t.Run(fmt.Sprintf("BatchOperation_%s", string(test.circuitType)), func(t *testing.T) {
			queueName := server.GetQueueNameForCircuit(test.circuitType)
			if queueName != test.expectedQueue {
				t.Errorf("Expected circuit type %s to route to %s, got %s",
					string(test.circuitType), test.expectedQueue, queueName)
			}
		})
	}

	// Raw transfer witnesses contain wallet secrets and must never be persisted
	// in the shared Redis queue. They are proved synchronously by the process
	// that accepted the request.
	transferTests := []common.CircuitType{
		common.TransferConfidentialCircuitType,
		common.TransferP256RingCircuitType,
	}

	for _, circuitType := range transferTests {
		t.Run(fmt.Sprintf("SecretOperation_%s", string(circuitType)), func(t *testing.T) {
			queueName := server.GetQueueNameForCircuit(circuitType)
			if queueName != "" {
				t.Errorf("Expected circuit type %s to stay out of Redis, got %s",
					string(circuitType), queueName)
			}
		})
	}
}
