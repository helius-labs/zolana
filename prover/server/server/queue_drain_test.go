package server

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	redisserver "github.com/alicebob/miniredis/v2/server"
)

func TestQueueWorkersDrainBeforeWaitReturns(t *testing.T) {
	ready := readyNow()
	constructors := map[string]func(*RedisQueue) *BaseQueueWorker{
		"append": func(q *RedisQueue) *BaseQueueWorker {
			return NewAddressAppendQueueWorker(WorkerConfig{Queue: q, Ready: ready})
		},
		"ring": func(q *RedisQueue) *BaseQueueWorker {
			return NewCustomRingQueueWorker(WorkerConfig{Queue: q, Ready: ready})
		},
		"transfer": func(q *RedisQueue) *BaseQueueWorker {
			return NewTransferQueueWorker(WorkerConfig{Queue: q, Ready: ready}, NewExecution(1))
		},
	}
	for name, create := range constructors {
		t.Run(name, func(t *testing.T) {
			redis, queue := newTestQueue(t)
			worker := create(queue)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			redis.Server().SetPreHook(func(_ *redisserver.Peer, command string, args ...string) bool {
				if strings.EqualFold(command, "rpush") && len(args) > 0 && args[0] == worker.processingQueueName {
					close(entered)
					<-release
				}
				return false
			})
			job := &ProofJob{ID: name, Payload: json.RawMessage(`{"circuitType":"unsupported"}`), CreatedAt: time.Now()}
			if err := queue.EnqueueProof(worker.queueName, job); err != nil {
				t.Fatal(err)
			}
			worker.processJobs(false)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("job did not enter processing")
			}
			worker.Stop()
			worker.Stop()
			go worker.Start()
			waited := make(chan struct{})
			go func() { worker.Wait(); close(waited) }()
			select {
			case <-waited:
				t.Error("worker stopped before its job finished")
			case <-time.After(20 * time.Millisecond):
			}
			unblock()
			select {
			case <-waited:
			case <-time.After(time.Second):
				t.Fatal("worker did not stop after its job finished")
			}
			if count, err := queue.Client.LLen(queue.Ctx, "zk_failed_queue").Result(); err != nil || count != 1 {
				t.Fatalf("job completion count %d with error %v", count, err)
			}
		})
	}
}
