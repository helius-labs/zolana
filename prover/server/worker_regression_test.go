package main_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
	"zolana/prover/prover/common"
	"zolana/prover/server"
)

// hangingBatchAppendPayload parses as a valid address-append request whose
// proving key is pinned in the lockfile, so the worker's prove goroutine
// blocks inside the key download and keeps its concurrency slot.
const hangingBatchAppendPayload = `{"circuitType":"address-append","treeHeight":40,"batchSize":10,` +
	`"publicInputHash":"0x1","oldRoot":"0x1","newRoot":"0x1","hashchainHash":"0x1","startIndex":0}`

// A dequeued job exists in no Redis queue. A worker that stops while the job
// waits for a concurrency slot must fail it, not strand it.
func TestStoppedWorkerFailsTheDequeuedJob(t *testing.T) {
	store := newHangingKeyStore(t)
	t.Setenv("ZOLANA_PROVING_KEYS_URL", store.URL())
	t.Setenv("PROVER_MAX_CONCURRENCY", "1")

	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	keyManager := common.NewLazyKeyManager(t.TempDir(), &common.DownloadConfig{MaxRetries: 1, AutoDownload: true})
	worker := server.NewAddressAppendQueueWorker(rq, keyManager)

	holdJob := &server.ProofJob{
		ID:         "hold-job",
		Type:       "zk_proof",
		Payload:    json.RawMessage(hangingBatchAppendPayload),
		CreatedAt:  time.Now(),
		BatchIndex: -1,
	}
	stuckJob := &server.ProofJob{
		ID:         "stuck-job",
		Type:       "zk_proof",
		Payload:    json.RawMessage(`{"circuitType":"address-append","treeHeight":40,"batchSize":10,"marker":"stuck"}`),
		CreatedAt:  time.Now(),
		BatchIndex: -1,
	}
	for _, job := range []*server.ProofJob{holdJob, stuckJob} {
		if err := rq.EnqueueProof("zk_address_append_queue", job); err != nil {
			t.Fatalf("enqueue %s: %v", job.ID, err)
		}
	}

	go worker.Start()
	defer store.Release()

	// The hold job owns the only slot once its key download starts. The stuck
	// job is out of Redis when its input hash lands.
	store.AwaitFirstDownload(t)
	awaitRedisKey(t, rq, "zk_input_hash_stuck-job")

	// Stop blocks on the in-flight hold job, the stuck job must not wait on it.
	go worker.Stop()

	awaitFailedJob(t, rq, "stuck-job")
}

// A job that cannot enter the processing queue must be failed so the waiting
// client is answered instead of polling a job no queue holds.
func TestJobThatCannotEnterProcessingIsFailed(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	// A string at the processing queue key fails every push to it with
	// WRONGTYPE while the rest of the queue keeps working.
	if err := rq.Client.Set(context.Background(), "zk_address_append_processing_queue", "blocker", 0).Err(); err != nil {
		t.Fatalf("plant the processing queue blocker: %v", err)
	}

	worker := server.NewAddressAppendQueueWorker(rq, nil)
	job := &server.ProofJob{
		ID:         "orphan-job",
		Type:       "zk_proof",
		Payload:    json.RawMessage(`{"circuitType":"address-append","treeHeight":40,"batchSize":10}`),
		CreatedAt:  time.Now(),
		BatchIndex: -1,
	}
	if err := rq.EnqueueProof("zk_address_append_queue", job); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	go worker.Start()
	defer worker.Stop()

	reply, err := rq.WaitReply(job.ID, 5*time.Second)
	if err != nil {
		t.Fatalf("wait for the job reply: %v", err)
	}
	if reply == nil {
		t.Fatal("no reply for a job that could not enter the processing queue")
	}
	if reply.Status != server.JobReplyFailed {
		t.Fatalf("expected a failed reply, got %q", reply.Status)
	}
	awaitFailedJob(t, rq, job.ID)
}

func awaitRedisKey(t *testing.T, rq *server.RedisQueue, key string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		exists, err := rq.Client.Exists(context.Background(), key).Result()
		if err != nil {
			t.Fatalf("check %s: %v", key, err)
		}
		if exists > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("key %s never appeared", key)
}

func awaitFailedJob(t *testing.T, rq *server.RedisQueue, jobID string) {
	t.Helper()
	wantID := jobID + "_failed"
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		items, err := rq.Client.LRange(context.Background(), "zk_failed_queue", 0, -1).Result()
		if err != nil {
			t.Fatalf("read the failed queue: %v", err)
		}
		for _, item := range items {
			var failed server.ProofJob
			if json.Unmarshal([]byte(item), &failed) == nil && failed.ID == wantID {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("job %s never reached the failed queue", jobID)
}

// hangingKeyStore stands in for the proving-key object store. Downloads block
// until Release, so a proof that reaches the key loader stays in flight.
type hangingKeyStore struct {
	server      *httptest.Server
	firstOnce   sync.Once
	first       chan struct{}
	releaseOnce sync.Once
	release     chan struct{}
}

func newHangingKeyStore(t *testing.T) *hangingKeyStore {
	store := &hangingKeyStore{
		first:   make(chan struct{}),
		release: make(chan struct{}),
	}
	store.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		store.firstOnce.Do(func() { close(store.first) })
		<-store.release
		w.WriteHeader(http.StatusNotFound)
	}))
	// Release must run before Close, which waits for in-flight handlers.
	t.Cleanup(store.server.Close)
	t.Cleanup(store.Release)
	return store
}

func (store *hangingKeyStore) URL() string { return store.server.URL }

func (store *hangingKeyStore) Release() {
	store.releaseOnce.Do(func() { close(store.release) })
}

func (store *hangingKeyStore) AwaitFirstDownload(t *testing.T) {
	t.Helper()
	select {
	case <-store.first:
	case <-time.After(10 * time.Second):
		t.Fatal("no proof reached the key store")
	}
}
