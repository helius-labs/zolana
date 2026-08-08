package server

import (
	"testing"
	"time"
)

// The dequeue loop feeds every proof worker, so its per-job cost caps the
// admission rate. The stages attribute a stall to no work, the dedup lookups,
// or backpressure from a full semaphore. Asserts on the rolling window
// because a Prometheus Gauge is write-only.
func TestDispatchStageTracksMeanAndMax(t *testing.T) {
	dispatchStages.byCircuit = map[string]*window{}

	dispatchStages.observe("zk_transfer_queue|dedup", 1, 0)
	mean, max, _ := dispatchStages.observe("zk_transfer_queue|dedup", 3, 0)

	if mean != 2 {
		t.Errorf("mean = %v, want 2", mean)
	}
	if max != 3 {
		t.Errorf("max = %v, want 3", max)
	}
}

// A slow stage must be attributable, so stages must not share a window.
func TestDispatchStagesDoNotShareAWindow(t *testing.T) {
	dispatchStages.byCircuit = map[string]*window{}

	RecordDispatchStage("zk_transfer_queue", "dequeue", 5*time.Second)
	RecordDispatchStage("zk_transfer_queue", "dedup", 10*time.Millisecond)

	dequeue, ok := dispatchStages.byCircuit["zk_transfer_queue|dequeue"]
	if !ok {
		t.Fatal("no window for the dequeue stage")
	}
	dedup, ok := dispatchStages.byCircuit["zk_transfer_queue|dedup"]
	if !ok {
		t.Fatal("no window for the dedup stage")
	}
	if len(dequeue.samples) != 1 || dequeue.samples[0] != 5 {
		t.Errorf("dequeue samples = %v, want [5]", dequeue.samples)
	}
	if len(dedup.samples) != 1 || dedup.samples[0] != 0.01 {
		t.Errorf("dedup samples = %v, want [0.01]", dedup.samples)
	}
}

// Queues are tracked separately too: the transfer loop and the address-append
// loop are different goroutines with different workloads.
func TestDispatchStagesKeepQueuesApart(t *testing.T) {
	dispatchStages.byCircuit = map[string]*window{}

	RecordDispatchStage("zk_transfer_queue", "dedup", 1*time.Second)
	RecordDispatchStage("zk_address_append_queue", "dedup", 20*time.Second)

	transfer := dispatchStages.byCircuit["zk_transfer_queue|dedup"]
	if transfer == nil || transfer.samples[0] != 1 {
		t.Errorf("transfer dedup = %v, want [1]", transfer)
	}
}

// A clock that has gone backwards must not publish a negative stage duration.
func TestRecordDispatchStageIgnoresNegativeDurations(t *testing.T) {
	dispatchStages.byCircuit = map[string]*window{}

	RecordDispatchStage("zk_transfer_queue", "dedup", 2*time.Second)
	RecordDispatchStage("zk_transfer_queue", "dedup", -1*time.Second)

	w, ok := dispatchStages.byCircuit["zk_transfer_queue|dedup"]
	if !ok {
		t.Fatal("no window recorded")
	}
	if len(w.samples) != 1 {
		t.Errorf("samples = %v, want the negative sample to be dropped", w.samples)
	}
}
