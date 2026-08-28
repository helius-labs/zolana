package server

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"

	"zolana/prover/logging"
)

// Bound on proofs proved inside a request, and on callers waiting for a slot.
//
// gnark spreads one proof across every free core, so admitting N at once does
// not finish them any sooner -- it multiplies each one's wall time by roughly N.
// Measured on devnet: uncontended proofs land at 143ms p50 (p90 150ms), while
// runs with several in flight per instance sat at 400-500ms for the same
// circuits. The queue path has always had this bound (getMaxConcurrency); the
// sync path had none, which is why transfer and merge were routed to the queue
// rather than answered directly.
//
// Waiting is deliberately bounded too. A permit-less caller parked on a
// connection for as long as it takes is how a burst turns into a pile of held
// connections and a load balancer timing out; past the wait bound the server
// says so with 429 and a Retry-After instead.
const (
	// Waiters allowed to queue behind the permits before the server sheds load.
	// Enough to absorb a burst that the in-flight proofs will drain shortly, not
	// enough to hide a prover that is simply undersized.
	syncWaitMultiple = 4
	// Seconds a shed caller is asked to wait. One proof's worth, rounded up: by
	// then a permit has almost certainly turned over.
	syncRetryAfterSecs = 1
)

// syncAdmission bounds concurrent in-request proving.
type syncAdmission struct {
	permits chan struct{}
	waiting atomic.Int64
	maxWait int64
}

func newSyncAdmission(permits int) *syncAdmission {
	if permits < 1 {
		permits = 1
	}
	logging.Logger().Info().
		Int("permits", permits).
		Int64("max_waiting", int64(permits*syncWaitMultiple)).
		Msg("Sync proof admission control")
	return &syncAdmission{
		permits: make(chan struct{}, permits),
		maxWait: int64(permits * syncWaitMultiple),
	}
}

// syncPermits is the in-request proving bound. PROVER_SYNC_CONCURRENCY overrides
// it; otherwise the sync path uses the same bound as a queue worker, so moving a
// circuit between the two rails does not change how much work an instance takes
// on at once.
func syncPermits() int {
	if val := os.Getenv("PROVER_SYNC_CONCURRENCY"); val != "" {
		if permits, err := strconv.Atoi(val); err == nil && permits > 0 {
			return permits
		}
		logging.Logger().Warn().
			Str("value", val).
			Msg("Ignoring unparseable PROVER_SYNC_CONCURRENCY")
	}
	return getMaxConcurrency()
}

// admit takes a permit, waiting until ctx expires. The returned release must be
// called exactly once, when the proof is done rather than when the handler
// returns: a handler that gives up on its deadline leaves the proof running, and
// releasing early would admit work the CPU is still busy with.
//
// The error is nil iff a permit was taken.
func (a *syncAdmission) admit(ctx context.Context) (func(), *Error) {
	if waiting := a.waiting.Add(1); waiting > a.maxWait {
		a.waiting.Add(-1)
		SyncProofsShedTotal.Inc()
		return nil, overloadedError()
	}
	defer a.waiting.Add(-1)

	select {
	case a.permits <- struct{}{}:
		var once atomic.Bool
		return func() {
			// Guard the release so a double call cannot hand out a permit that
			// was never held.
			if once.CompareAndSwap(false, true) {
				<-a.permits
			}
		}, nil
	case <-ctx.Done():
		SyncProofsShedTotal.Inc()
		return nil, overloadedError()
	}
}

func overloadedError() *Error {
	return &Error{
		StatusCode: http.StatusTooManyRequests,
		Code:       "prover_busy",
		Message:    "Prover is at its concurrency limit; retry shortly or submit with X-Async: true",
	}
}

// sendWithRetryAfter sheds a caller, telling it when to come back. Without the
// header a client is left to guess, and guessing wrong is what turns a shed
// request into a retry storm.
func sendOverloaded(w http.ResponseWriter, e *Error) {
	w.Header().Set("Retry-After", strconv.Itoa(syncRetryAfterSecs))
	e.send(w)
}
