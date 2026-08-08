package server

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Capacity planning divides by prover_proof_requests_total, so a double count
// doubles the apparent cost of every transfer. proveHandler counts each
// request once at the routing point. StartProofTimer owns execution-side
// metrics only.
func TestStartProofTimerDoesNotCountRequests(t *testing.T) {
	const circuit = "transfer-confidential"

	before := testutil.ToFloat64(ProofRequestsTotal.WithLabelValues(circuit))

	timer := StartProofTimer(circuit)
	timer.ObserveDuration()

	after := testutil.ToFloat64(ProofRequestsTotal.WithLabelValues(circuit))

	if after != before {
		t.Errorf(
			"StartProofTimer changed ProofRequestsTotal by %v; the request is "+
				"already counted by the handler, so counting it here doubles it",
			after-before,
		)
	}
}

// The execution-side metric StartProofTimer does own. Guards against the
// opposite mistake: stripping the counter increment and taking ActiveJobs with
// it, which would leave nothing tracking in-flight proofs -- the gauge that
// showed the prover pinned at its concurrency limit.
func TestStartProofTimerTracksActiveJobs(t *testing.T) {
	const circuit = "transfer-confidential"

	before := testutil.ToFloat64(ActiveJobs)

	timer := StartProofTimer(circuit)
	during := testutil.ToFloat64(ActiveJobs)
	if during != before+1 {
		t.Errorf("ActiveJobs = %v while proving, want %v", during, before+1)
	}

	timer.ObserveDuration()
	after := testutil.ToFloat64(ActiveJobs)
	if after != before {
		t.Errorf("ActiveJobs = %v after completion, want %v", after, before)
	}
}
