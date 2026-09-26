package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"zolana/prover/prover/indexed"

	"github.com/alicebob/miniredis/v2"
	redisserver "github.com/alicebob/miniredis/v2/server"
)

func newTestQueue(t *testing.T) (*miniredis.Miniredis, *RedisQueue) {
	t.Helper()
	redis := miniredis.RunT(t)
	queue, err := NewRedisQueue("redis://" + redis.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Client.Close() })
	return redis, queue
}

func readyNow() <-chan struct{} {
	ready := make(chan struct{})
	close(ready)
	return ready
}

// Holds every execution permit, so a popped job waits for one.
func busyTransferWorker(queue *RedisQueue) *BaseQueueWorker {
	execution := NewExecution(1)
	execution.admission.permits <- struct{}{}
	return NewTransferQueueWorker(WorkerConfig{Queue: queue, Ready: readyNow()}, execution)
}

func testJob(id string) *ProofJob {
	return &ProofJob{ID: id, Payload: json.RawMessage(`{"circuitType":"transfer","id":"` + id + `"}`), CreatedAt: time.Now()}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestIndexedJobsLiveOnTheirOwnKey(t *testing.T) {
	_, queue := newTestQueue(t)
	job := testJob("resolvable")
	job.Indexed = true
	if err := queue.EnqueueProof("zk_transfer_queue", job); err != nil {
		t.Fatal(err)
	}
	stored, err := queue.Client.LIndex(queue.Ctx, "zk_transfer_indexed_queue", 0).Result()
	if err != nil || strings.Contains(stored, `"indexed"`) {
		t.Fatalf("indexed job stored as %q with error %v", stored, err)
	}
	if stats, err := queue.GetQueueStats(); err != nil || stats["zk_transfer_queue"] != 1 {
		t.Fatalf("indexed depth missing from stats %v with error %v", stats, err)
	}
	if popped, err := queue.DequeueProof("zk_transfer_queue", 50*time.Millisecond); err != nil || popped != nil {
		t.Fatalf("plain pop returned %+v with error %v", popped, err)
	}
	popped, err := queue.DequeueIndexedProof("zk_transfer_queue", 50*time.Millisecond)
	if err != nil || popped == nil || !popped.Indexed || popped.ID != job.ID {
		t.Fatalf("indexed pop returned %+v with error %v", popped, err)
	}
}

func blockingPhoton(t *testing.T) (*indexed.Resolver, <-chan struct{}) {
	t.Helper()
	release, received := make(chan struct{}), make(chan struct{}, 16)
	photon := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		received <- struct{}{}
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(photon.Close)
	t.Cleanup(func() { close(release) })
	resolver, err := indexed.NewResolver(indexed.Config{URL: photon.URL, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	return resolver, received
}

func TestEveryWorkerResolvesIndexedJobs(t *testing.T) {
	constructors := map[string]func(WorkerConfig) *BaseQueueWorker{
		"append": NewAddressAppendQueueWorker,
		"ring":   NewCustomRingQueueWorker,
		"transfer": func(config WorkerConfig) *BaseQueueWorker {
			return NewTransferQueueWorker(config, NewExecution(1))
		},
	}
	for name, create := range constructors {
		t.Run(name, func(t *testing.T) {
			resolver, received := blockingPhoton(t)
			_, queue := newTestQueue(t)
			worker := create(WorkerConfig{Queue: queue, Indexer: resolver, Ready: readyNow()})
			job := &ProofJob{ID: name, Indexed: true, Payload: indexedTransferRequest(t), CreatedAt: time.Now()}
			if err := queue.EnqueueProof(worker.queueName, job); err != nil {
				t.Fatal(err)
			}
			go worker.Start()
			select {
			case <-received:
			case <-time.After(5 * time.Second):
				t.Fatal("indexed job was never resolved")
			}
			worker.Stop()
			worker.Wait()
		})
	}
}

func TestSlowIndexerDoesNotHoldPlainJobs(t *testing.T) {
	resolver, received := blockingPhoton(t)
	_, queue := newTestQueue(t)
	worker := NewTransferQueueWorker(WorkerConfig{Queue: queue, Indexer: resolver, Ready: readyNow()}, NewExecution(1))
	slow := &ProofJob{ID: "slow", Indexed: true, Payload: indexedTransferRequest(t), CreatedAt: time.Now()}
	if err := queue.EnqueueProof(worker.queueName, slow); err != nil {
		t.Fatal(err)
	}
	go worker.Start()
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("indexed job was never resolved")
	}
	if err := queue.EnqueueProof(worker.queueName, testJob("plain")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return queue.Client.LLen(queue.Ctx, "zk_failed_queue").Val() == 1 })
	worker.Stop()
	worker.Wait()
	head, err := queue.DequeueIndexedProof(worker.queueName, 50*time.Millisecond)
	if err != nil || head == nil || head.ID != slow.ID {
		t.Fatalf("stopped resolution left %+v with error %v", head, err)
	}
	if len(worker.resolving) != 0 {
		t.Fatal("stopped resolution kept its slot")
	}
}

func TestStopReturnsWaitingJobToTheHead(t *testing.T) {
	_, queue := newTestQueue(t)
	worker := busyTransferWorker(queue)
	for _, id := range []string{"first", "second"} {
		if err := queue.EnqueueProof(worker.queueName, testJob(id)); err != nil {
			t.Fatal(err)
		}
	}
	handled := make(chan struct{})
	go func() {
		worker.processJobs(false)
		close(handled)
	}()
	waitFor(t, func() bool { return queue.Client.LLen(queue.Ctx, worker.queueName).Val() == 1 })
	worker.Stop()
	<-handled
	head, err := queue.DequeueProof(worker.queueName, 50*time.Millisecond)
	if err != nil || head == nil || head.ID != "first" {
		t.Fatalf("queue head is %+v with error %v", head, err)
	}
}

func TestFailedRequeueFailsWithoutCachingTheInput(t *testing.T) {
	redis, queue := newTestQueue(t)
	worker := busyTransferWorker(queue)
	job := testJob("lost")
	if err := queue.StoreJobMeta(job.ID, worker.queueName, "transfer"); err != nil {
		t.Fatal(err)
	}
	inputHash := ComputeInputHash(job.Payload)
	if err := queue.SetInFlightJob(inputHash, job.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := queue.EnqueueProof(worker.queueName, job); err != nil {
		t.Fatal(err)
	}
	redis.Server().SetPreHook(func(peer *redisserver.Peer, command string, _ ...string) bool {
		if strings.EqualFold(command, "lpush") {
			peer.WriteError("ERR refused")
			return true
		}
		return false
	})
	handled := make(chan struct{})
	go func() {
		worker.processJobs(false)
		close(handled)
	}()
	waitFor(t, func() bool { return queue.Client.LLen(queue.Ctx, worker.queueName).Val() == 0 })
	worker.Stop()
	<-handled
	meta, err := queue.GetJobMeta(job.ID)
	if err != nil || meta["status"] != "failed" {
		t.Fatalf("job meta %v with error %v", meta, err)
	}
	if redis.Exists("zk_inflight_" + inputHash) {
		t.Fatal("failed job kept its in-flight marker")
	}
	if cached, _, err := queue.FindCachedFailure(inputHash); err != nil || cached != nil {
		t.Fatalf("stop failure was cached for the input %v with error %v", cached, err)
	}
}
