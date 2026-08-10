package main_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
	"zolana/prover/server"

	"github.com/redis/go-redis/v9"
)

// passthroughHook keeps every stage it does not override.
type passthroughHook struct{}

func (passthroughHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (passthroughHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return next
}
func (passthroughHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// shortBlpopHook answers every blocking pop with a single element, the shape
// of a truncated server reply.
type shortBlpopHook struct{ passthroughHook }

func (shortBlpopHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "blpop" {
			if c, ok := cmd.(*redis.StringSliceCmd); ok {
				c.SetVal([]string{"zk_reply:short"})
				return nil
			}
		}
		return next(ctx, cmd)
	}
}

// A truncated reply must surface as an error, not a crash and not a
// fabricated reply body.
func TestShortBlockingPopReplyIsAnError(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)
	rq.Client.AddHook(shortBlpopHook{})

	reply, err := rq.WaitReply("short", time.Second)
	if err == nil {
		t.Fatalf("expected an error for a short reply, got reply %+v", reply)
	}
}

// sAddFailureHook fails every set add, alone and inside a transaction, the
// way one lost command on a flaky connection does.
type sAddFailureHook struct{ passthroughHook }

var errInjectedSAdd = errors.New("injected sadd failure")

func (sAddFailureHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "sadd" {
			cmd.SetErr(errInjectedSAdd)
			return errInjectedSAdd
		}
		return next(ctx, cmd)
	}
}

func (sAddFailureHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			if cmd.Name() == "sadd" {
				for _, c := range cmds {
					c.SetErr(errInjectedSAdd)
				}
				return errInjectedSAdd
			}
		}
		return next(ctx, cmds)
	}
}

// The trees set is the only path the fair dequeue reaches a tree sub-queue
// through. An enqueue that cannot record the tree must fail loudly, a
// reported success whose job no worker can reach is a lost proof.
func TestEnqueueWithFailedTreeTrackingIsNotSilent(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)
	rq.Client.AddHook(sAddFailureHook{})

	job := &server.ProofJob{
		ID:         "tree-job",
		Type:       "zk_proof",
		Payload:    json.RawMessage(`{"circuitType":"address-append"}`),
		CreatedAt:  time.Now(),
		TreeID:     "tree-a",
		BatchIndex: 0,
	}
	if err := rq.EnqueueProof("zk_address_append_queue", job); err != nil {
		return
	}

	dequeued, err := rq.DequeueProof("zk_address_append_queue", 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dequeue after a reported-success enqueue: %v", err)
	}
	if dequeued == nil {
		t.Fatal("enqueue reported success but no worker can reach the job")
	}
}

// lRemContentionHook answers every list remove with zero and removes nothing,
// the way a faster worker looks to the loser of every race.
type lRemContentionHook struct{ passthroughHook }

func (lRemContentionHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "lrem" {
			if c, ok := cmd.(*redis.IntCmd); ok {
				c.SetVal(0)
				return nil
			}
		}
		return next(ctx, cmd)
	}
}

// A dequeue that loses every removal race must hand the queue back, not spin
// on it forever.
func TestDequeueReturnsUnderPermanentRemoveContention(t *testing.T) {
	rq := setupRedisQueue(t)
	defer teardownRedisQueue(t, rq)

	ctx := context.Background()
	if err := rq.Client.SAdd(ctx, "zk_address_append_queue:trees", "tree-a").Err(); err != nil {
		t.Fatalf("seed the trees set: %v", err)
	}
	for index, id := range []string{"job-a", "job-b"} {
		data, err := json.Marshal(&server.ProofJob{
			ID:         id,
			Type:       "zk_proof",
			Payload:    json.RawMessage(`{"circuitType":"address-append"}`),
			CreatedAt:  time.Now(),
			TreeID:     "tree-a",
			BatchIndex: int64(index),
		})
		if err != nil {
			t.Fatalf("marshal %s: %v", id, err)
		}
		if err := rq.Client.RPush(ctx, "zk_address_append_queue:tree-a", data).Err(); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	rq.Client.AddHook(lRemContentionHook{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		rq.DequeueProof("zk_address_append_queue", 200*time.Millisecond)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dequeue never returned while every remove lost the race")
	}
}
