package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"zolana/prover/prover/common"

	"github.com/alicebob/miniredis/v2"
)

func waitTestQueue(t *testing.T) *RedisQueue {
	t.Helper()
	rq, err := NewRedisQueue("redis://" + miniredis.RunT(t).Addr() + "/0")
	if err != nil {
		t.Fatalf("NewRedisQueue: %v", err)
	}
	if err := rq.Client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("FlushDB: %v", err)
	}
	return rq
}

// A pushed reply must wake the blocked waiter and carry the result, so the
// client needs no follow-up poll.
func TestWaitEndpointDeliversPushedReply(t *testing.T) {
	rq := waitTestQueue(t)
	const jobID = "11111111-1111-4111-8111-111111111111"

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = rq.PushReply(jobID, &JobReply{
			Status:     JobReplyCompleted,
			Result:     json.RawMessage(`{"proof":"x"}`),
			Queue:      "zk_transfer_queue",
			FinishedAt: time.Now(),
		})
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/prove/wait?job_id="+jobID+"&timeout_s=5", nil)
	proofWaitHandler{redisQueue: rq}.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Status string          `json:"status"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body.Status != "completed" || string(body.Result) != `{"proof":"x"}` {
		t.Errorf("body = %s", rec.Body.String())
	}
}

// Without a reply the endpoint answers 202 within the timeout, and the stored
// result stays reachable through polling. The fallback contract.
func TestWaitEndpointTimesOutToPolling(t *testing.T) {
	rq := waitTestQueue(t)
	const jobID = "22222222-2222-4222-8222-222222222222"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/prove/wait?job_id="+jobID+"&timeout_s=1", nil)
	start := time.Now()
	proofWaitHandler{redisQueue: rq}.ServeHTTP(rec, req)
	if rec.Code != 202 {
		t.Fatalf("status = %d, want 202, body %s", rec.Code, rec.Body.String())
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("wait exceeded its timeout")
	}
}

// A result stored before the wait answers immediately, an expired or consumed
// reply must not matter.
func TestWaitEndpointServesStoredResultWithoutReply(t *testing.T) {
	rq := waitTestQueue(t)
	const jobID = "33333333-3333-4333-8333-333333333333"

	if err := rq.StoreResult(jobID, &common.ProofWithTiming{ProofDurationMs: 271}); err != nil {
		t.Fatalf("StoreResult: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/prove/wait?job_id="+jobID+"&timeout_s=1", nil)
	proofWaitHandler{redisQueue: rq}.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body %s", rec.Code, rec.Body.String())
	}
}

// A failed reply is a final answer with the error attached.
func TestWaitEndpointReportsFailure(t *testing.T) {
	rq := waitTestQueue(t)
	const jobID = "44444444-4444-4444-8444-444444444444"

	if err := rq.PushReply(jobID, &JobReply{
		Status:     JobReplyFailed,
		Error:      "invalid witness",
		Queue:      "zk_transfer_queue",
		FinishedAt: time.Now(),
	}); err != nil {
		t.Fatalf("PushReply: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/prove/wait?job_id="+jobID+"&timeout_s=2", nil)
	proofWaitHandler{redisQueue: rq}.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body.Status != "failed" || body.Error != "invalid witness" {
		t.Errorf("body = %s", rec.Body.String())
	}
}

// WaitReply restores the reply after pickup, so a second waiter is served too.
func TestWaitReplyServesLateWaiters(t *testing.T) {
	rq := waitTestQueue(t)
	const jobID = "55555555-5555-4555-8555-555555555555"

	if err := rq.PushReply(jobID, &JobReply{Status: JobReplyCompleted, FinishedAt: time.Now()}); err != nil {
		t.Fatalf("PushReply: %v", err)
	}
	first, err := rq.WaitReply(jobID, time.Second)
	if err != nil || first == nil {
		t.Fatalf("first WaitReply = %v, %v", first, err)
	}
	second, err := rq.WaitReply(jobID, time.Second)
	if err != nil || second == nil {
		t.Fatalf("second WaitReply = %v, %v", second, err)
	}
}
