package main_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// The status endpoint answers from the job's metadata, so the metadata has to
// carry a status that is actually current. These tests pin that: every
// transition a job can make must be visible without looking in a queue.
//
// The scans they replace were not a micro-optimisation. checkJobExistsDetailed
// walked up to four whole Redis lists per poll, and a client polls from
// submission until its proof lands, so the cost scaled with queue length times
// poll rate. With 8237 entries in zk_results_queue it saturated Redis, and the
// prover tasks were killed by failing health checks.

func TestJobStatusStartsQueued(t *testing.T) {
	queue := setupRedisQueue(t)
	jobID := uuid.NewString()

	if err := queue.StoreJobMeta(jobID, "zk_transfer_queue", "transfer"); err != nil {
		t.Fatalf("store job meta: %v", err)
	}

	meta, err := queue.GetJobMeta(jobID)
	if err != nil {
		t.Fatalf("get job meta: %v", err)
	}
	if got := meta["status"]; got != "queued" {
		t.Fatalf("status = %v, want queued", got)
	}
}

func TestMarkJobProcessingIsVisibleWithoutScanningQueues(t *testing.T) {
	queue := setupRedisQueue(t)
	jobID := uuid.NewString()

	if err := queue.StoreJobMeta(jobID, "zk_transfer_queue", "transfer"); err != nil {
		t.Fatalf("store job meta: %v", err)
	}
	if err := queue.MarkJobProcessing(jobID); err != nil {
		t.Fatalf("mark processing: %v", err)
	}

	meta, err := queue.GetJobMeta(jobID)
	if err != nil {
		t.Fatalf("get job meta: %v", err)
	}
	if got := meta["status"]; got != "processing" {
		t.Fatalf("status = %v, want processing", got)
	}
	// The fields written at submission have to survive the update -- the status
	// response still reports them.
	if got := meta["circuit_type"]; got != "transfer" {
		t.Fatalf("circuit_type = %v, want transfer", got)
	}
	if got := meta["queue"]; got != "zk_transfer_queue" {
		t.Fatalf("queue = %v, want zk_transfer_queue", got)
	}
}

func TestMarkJobProcessingKeepsTheSubmissionExpiry(t *testing.T) {
	queue := setupRedisQueue(t)
	jobID := uuid.NewString()

	if err := queue.StoreJobMeta(jobID, "zk_transfer_queue", "transfer"); err != nil {
		t.Fatalf("store job meta: %v", err)
	}
	key := "zk_job_meta_" + jobID
	before := queue.Client.TTL(queue.Ctx, key).Val()

	if err := queue.MarkJobProcessing(jobID); err != nil {
		t.Fatalf("mark processing: %v", err)
	}

	after := queue.Client.TTL(queue.Ctx, key).Val()
	if after <= 0 {
		t.Fatalf("TTL = %v, want the submission expiry preserved (never unbounded)", after)
	}
	// Picking a job up must not extend its life; a job that is never finished
	// still has to age out.
	if after > before {
		t.Fatalf("TTL grew from %v to %v; processing should not renew it", before, after)
	}
}

func TestMarkJobFailedCarriesTheReason(t *testing.T) {
	queue := setupRedisQueue(t)
	jobID := uuid.NewString()

	if err := queue.StoreJobMeta(jobID, "zk_transfer_queue", "transfer"); err != nil {
		t.Fatalf("store job meta: %v", err)
	}
	details := map[string]interface{}{
		"error":     "proof generation failed",
		"failed_at": time.Now(),
	}
	if err := queue.MarkJobFailed(jobID, details); err != nil {
		t.Fatalf("mark failed: %v", err)
	}

	meta, err := queue.GetJobMeta(jobID)
	if err != nil {
		t.Fatalf("get job meta: %v", err)
	}
	if got := meta["status"]; got != "failed" {
		t.Fatalf("status = %v, want failed", got)
	}
	failure, ok := meta["failure"].(map[string]interface{})
	if !ok {
		t.Fatalf("failure = %v, want the details map", meta["failure"])
	}
	if got := failure["error"]; got != "proof generation failed" {
		t.Fatalf("failure error = %v, want the original message", got)
	}
}

// The stuck-job reaper fails jobs that have been in the processing queue too
// long, and by then their metadata may already have expired. Recreating it is
// the difference between a client being told to stop and a client waiting out
// its entire deadline -- which is how 197 workers ended up parked for 35
// minutes against an idle prover.
func TestMarkJobFailedRecreatesExpiredMetadata(t *testing.T) {
	queue := setupRedisQueue(t)
	jobID := uuid.NewString()

	if meta, err := queue.GetJobMeta(jobID); err != nil || meta != nil {
		t.Fatalf("precondition: job should be unknown, got meta=%v err=%v", meta, err)
	}

	err := queue.MarkJobFailed(jobID, map[string]interface{}{
		"error":   "Job timed out in processing queue",
		"timeout": true,
	})
	if err != nil {
		t.Fatalf("mark failed: %v", err)
	}

	meta, err := queue.GetJobMeta(jobID)
	if err != nil {
		t.Fatalf("get job meta: %v", err)
	}
	if meta == nil {
		t.Fatal("a reaped job left no record; the client cannot learn it failed")
	}
	if got := meta["status"]; got != "failed" {
		t.Fatalf("status = %v, want failed", got)
	}
	// Recreated records must still expire, or a reaped job leaks a key forever.
	if ttl := queue.Client.TTL(queue.Ctx, "zk_job_meta_"+jobID).Val(); ttl <= 0 {
		t.Fatalf("TTL = %v, want a bounded lifetime", ttl)
	}
}
