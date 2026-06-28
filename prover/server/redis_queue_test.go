package main_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
	"zolana/prover/prover/common"
	"zolana/prover/server"

	"github.com/google/uuid"
)

const TestRedisURL = "redis://localhost:6379/15"

func setupRedisQueue(t *testing.T) *server.RedisQueue {
	// Skip if Redis URL not available
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		redisURL = TestRedisURL
	}

	rq, err := server.NewRedisQueue(redisURL)
	if err != nil {
		t.Skipf("Redis not available for testing: %v", err)
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

	// Create a mix of old and recent jobs across multiple queues
	now := time.Now()
	oldTime := now.Add(-35 * time.Minute)    // 35 minutes ago (should be removed)
	recentTime := now.Add(-20 * time.Minute) // 20 minutes ago (should stay)

	// Create test jobs for all input queues
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

	// Enqueue all test jobs
	for _, testJob := range testJobs {
		err := rq.EnqueueProof(testJob.queueName, testJob.job)
		if err != nil {
			t.Fatalf("Failed to enqueue test job to %s: %v", testJob.queueName, err)
		}
	}

	// Verify initial state
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

	// Run cleanup
	err = rq.CleanupOldRequests()
	if err != nil {
		t.Errorf("CleanupOldRequests failed: %v", err)
	}

	// Verify cleanup results
	stats, err = rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats after cleanup: %v", err)
	}

	// Count expected remaining jobs
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

	// Verify we can still dequeue the remaining address append job
	remainingAddress, err := rq.DequeueProof("zk_address_append_queue", 1*time.Second)
	if err != nil {
		t.Errorf("Failed to dequeue remaining address append job: %v", err)
	}
	if remainingAddress == nil {
		t.Errorf("Expected to find remaining address append job")
	}

	// Verify the address append queue is now empty (only the old job was cleaned up)
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

	// Create jobs with different ages
	now := time.Now()
	oldTime := now.Add(-45 * time.Minute)    // 45 minutes ago (should be removed)
	recentTime := now.Add(-15 * time.Minute) // 15 minutes ago (should stay)

	// Create old jobs (should be removed)
	oldAddressJob := &server.ProofJob{
		ID:        uuid.New().String(),
		Type:      "zk_proof",
		Payload:   json.RawMessage(`{"tree_height": 40, "batch_size": 10}`),
		CreatedAt: oldTime,
	}

	// Create recent jobs (should stay)
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

	// Enqueue all jobs
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

	// Verify initial state
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

	// Run cleanup
	err = rq.CleanupOldRequests()
	if err != nil {
		t.Errorf("CleanupOldRequests failed: %v", err)
	}

	// Verify cleanup results
	stats, err = rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats after cleanup: %v", err)
	}

	// The address append queue drops its old job; the failed queue is untouched
	if stats["zk_address_append_queue"] != 1 {
		t.Errorf("Expected zk_address_append_queue to have 1 job after cleanup, got %d", stats["zk_address_append_queue"])
	}
	if stats["zk_failed_queue"] != 2 {
		t.Errorf("Expected zk_failed_queue to have 2 jobs after cleanup, got %d", stats["zk_failed_queue"])
	}

	// Verify the remaining address append job is the recent one
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
		t.Errorf("Expected to dequeue a job, got nil")
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
		t.Errorf("Expected to dequeue a job, got nil")
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
		t.Errorf("Expected to dequeue a job, got nil")
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
	if duration > 1*time.Second {
		t.Errorf("Timeout duration too long: %v", duration)
	}
}

func TestQueueNameForCircuitType(t *testing.T) {
	tests := []struct {
		circuitType   common.CircuitType
		expectedQueue string
	}{
		{common.BatchAddressAppendCircuitType, "zk_address_append_queue"},
		{common.TransferConfidentialCircuitType, ""},     // Not queued
		{common.TransferP256ConfidentialCircuitType, ""}, // Not queued
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

	mockResult := map[string]interface{}{
		"proof":  "mock-proof-data",
		"status": "completed",
	}

	err := rq.StoreResult(jobID, mockResult)
	if err != nil {
		t.Errorf("Failed to store result: %v", err)
	}

	result, err := rq.GetResult(jobID)
	if err != nil {
		t.Errorf("Failed to retrieve result: %v", err)
	}
	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	if _, ok := result.(map[string]interface{}); !ok {
		t.Errorf("Expected result to be map[string]interface{}, got %T", result)
	}
}

func TestResultCleanup(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	for i := 0; i < 1005; i++ {
		job := &server.ProofJob{
			ID:        fmt.Sprintf("cleanup-job-%d", i),
			Type:      "result",
			Payload:   json.RawMessage(`{"test": "data"}`),
			CreatedAt: time.Now(),
		}
		err := rq.EnqueueProof("zk_results_queue", job)
		if err != nil {
			t.Fatalf("Failed to enqueue cleanup job %d: %v", i, err)
		}
	}

	err := rq.CleanupOldResults()
	if err != nil {
		t.Errorf("Failed to cleanup old results: %v", err)
	}

	stats, err := rq.GetQueueStats()
	if err != nil {
		t.Fatalf("Failed to get queue stats: %v", err)
	}
	if stats["zk_results_queue"] != int64(1000) {
		t.Errorf("Expected results queue to have 1000 jobs after cleanup, got %d", stats["zk_results_queue"])
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
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	keyManager := common.NewLazyKeyManager("./proving-keys/", common.DefaultDownloadConfig())

	config := &server.EnhancedConfig{
		ProverAddress:  "localhost:8082",
		MetricsAddress: "localhost:9997",
		Queue: &server.QueueConfig{
			RedisURL: TestRedisURL,
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

	// Read response body
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
	} else if !contains(message, errorMessage) {
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

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || strings.Contains(s, substr)))
}

func TestWorkerSelectionLogic(t *testing.T) {
	testCases := []struct {
		name          string
		circuits      []string
		expectAddress bool
	}{
		{
			name:          "Address append only",
			circuits:      []string{"address-append"},
			expectAddress: true,
		},
		{
			name:          "Address append test",
			circuits:      []string{"address-append-test"},
			expectAddress: true,
		},
		{
			name:          "Unrelated circuits only",
			circuits:      []string{"transfer", "transfer-p256"},
			expectAddress: false,
		},
		{
			name:          "Empty",
			circuits:      []string{},
			expectAddress: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shouldStartAddress := containsCircuit(tc.circuits, "address-append") || containsCircuit(tc.circuits, "address-append-test")

			if shouldStartAddress != tc.expectAddress {
				t.Errorf("Expected address append worker: %v, got: %v", tc.expectAddress, shouldStartAddress)
			}
		})
	}
}

func containsCircuit(circuits []string, circuit string) bool {
	for _, c := range circuits {
		if c == circuit {
			return true
		}
	}
	return false
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

	nonBatchTests := []common.CircuitType{
		common.TransferConfidentialCircuitType,
		common.TransferP256ConfidentialCircuitType,
	}

	for _, circuitType := range nonBatchTests {
		t.Run(fmt.Sprintf("NonBatchOperation_%s", string(circuitType)), func(t *testing.T) {
			queueName := server.GetQueueNameForCircuit(circuitType)
			expectedQueue := ""
			if queueName != expectedQueue {
				t.Errorf("Expected circuit type %s to route to %s, got %s",
					string(circuitType), expectedQueue, queueName)
			}
		})
	}
}
