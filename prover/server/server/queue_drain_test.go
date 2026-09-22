package server

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redisserver "github.com/alicebob/miniredis/v2/server"
)

func TestQueueWorkersDrainBeforeWaitReturns(t *testing.T) {
	constructors := map[string]func(*RedisQueue) *BaseQueueWorker{
		"append": func(q *RedisQueue) *BaseQueueWorker { return NewAddressAppendQueueWorker(q, nil).BaseQueueWorker },
		"ring":   func(q *RedisQueue) *BaseQueueWorker { return NewCustomRingQueueWorker(q, nil).BaseQueueWorker },
		"transfer": func(q *RedisQueue) *BaseQueueWorker {
			return NewTransferQueueWorker(TransferWorkerConfig{Queue: q}).BaseQueueWorker
		},
	}
	for name, create := range constructors {
		t.Run(name, func(t *testing.T) {
			redis := miniredis.RunT(t)
			queue, err := NewRedisQueue("redis://" + redis.Addr())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = queue.Client.Close() })
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
			worker.processJobs()
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
