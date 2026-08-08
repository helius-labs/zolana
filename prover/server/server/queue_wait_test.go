package server

import (
	"testing"
	"time"
)

// Pins the enqueue-to-dequeue wait metric. Asserts on the rolling window
// because a Prometheus Gauge is write-only.
func TestQueueWaitTracksMeanAndMax(t *testing.T) {
	queueWaits.byCircuit = map[string]*window{}

	queueWaits.observe("zk_transfer_queue", 2, 0)
	mean, max, _ := queueWaits.observe("zk_transfer_queue", 4, 0)

	if mean != 3 {
		t.Errorf("mean = %v, want 3", mean)
	}
	if max != 4 {
		t.Errorf("max = %v, want 4", max)
	}
}

// Queues are tracked separately: the transfer queue draining promptly says
// nothing about the batch queue behind it.
func TestQueueWaitKeepsQueuesApart(t *testing.T) {
	queueWaits.byCircuit = map[string]*window{}

	queueWaits.observe("zk_transfer_queue", 1, 0)
	mean, max, _ := queueWaits.observe("zk_update_queue", 30, 0)

	if mean != 30 || max != 30 {
		t.Errorf("update queue mean/max = %v/%v, want 30/30", mean, max)
	}
	transferMean, _, _ := queueWaits.observe("zk_transfer_queue", 1, 0)
	if transferMean != 1 {
		t.Errorf("transfer queue mean = %v, want 1 -- queues must not share a window", transferMean)
	}
}

// A clock that has gone backwards must not publish a negative wait, which would
// read as a queue returning results before they were submitted.
func TestRecordQueueWaitIgnoresNegativeDurations(t *testing.T) {
	queueWaits.byCircuit = map[string]*window{}

	RecordQueueWait("zk_transfer_queue", 5*time.Second)
	RecordQueueWait("zk_transfer_queue", -1*time.Second)

	w, ok := queueWaits.byCircuit["zk_transfer_queue"]
	if !ok {
		t.Fatal("no window recorded")
	}
	if len(w.samples) != 1 {
		t.Errorf("samples = %v, want the negative sample to be dropped", w.samples)
	}
}
