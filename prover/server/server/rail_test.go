package server

import "testing"

// The header has to decide the rail. It was parsed and logged but never
// consulted, so `X-Sync: true` returned a job handle anyway -- a client could
// not opt out of the poll schedule at all.
func TestUseQueueHonoursTheRequestedRail(t *testing.T) {
	for _, tc := range []struct {
		name                                          string
		forceSync, forceAsync, queued, queueAvailable bool
		want                                          bool
	}{
		{
			name: "a queueable circuit queues by default",
			// No headers: unchanged behaviour, which is what production runs on.
			queued: true, queueAvailable: true, want: true,
		},
		{
			name:      "X-Sync takes a queueable circuit off the queue",
			forceSync: true, queued: true, queueAvailable: true, want: false,
		},
		{
			name:       "X-Async wins a contradiction, because queueing cannot time out a connection",
			forceSync:  true,
			forceAsync: true, queued: true, queueAvailable: true, want: true,
		},
		{
			name:       "X-Async cannot queue a circuit that has no queue",
			forceAsync: true, queued: false, queueAvailable: true, want: false,
		},
		{
			name:   "a circuit without a queue is proved in the request",
			queued: false, queueAvailable: true, want: false,
		},
		{
			name: "no queue configured means every rail is the sync one",
			// A local prover with no Redis: X-Async must not route into a queue
			// that does not exist.
			forceAsync: true, queued: true, queueAvailable: false, want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := useQueue(tc.forceSync, tc.forceAsync, tc.queued, tc.queueAvailable)
			if got != tc.want {
				t.Fatalf("useQueue(sync=%v, async=%v, queued=%v, available=%v) = %v, want %v",
					tc.forceSync, tc.forceAsync, tc.queued, tc.queueAvailable, got, tc.want)
			}
		})
	}
}
