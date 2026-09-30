package server

import (
	"context"
	"testing"
	"time"

	"zolana/prover/prover/common"
)

func TestTransferExecutionSharesHTTPAndQueueCapacity(t *testing.T) {
	execution := &Execution{admission: newSyncAdmission(1)}
	queued, ok := execution.acquireQueued(make(chan struct{}))
	if !ok {
		t.Fatal("queue admission failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if release, err := admit(execution.admission, ctx); err == nil {
		release()
		t.Fatal("HTTP request exceeded shared capacity")
	}
	queued()
	queued()
	held, err := admit(execution.admission, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	stop := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		release, acquired := execution.acquireQueued(stop)
		if acquired {
			release()
		}
		done <- acquired
	}()
	close(stop)
	select {
	case acquired := <-done:
		if acquired {
			t.Fatal("stopped queue acquired an HTTP permit")
		}
	case <-time.After(time.Second):
		t.Fatal("queue admission ignored shutdown")
	}
}

func TestTransferDeliveryDefaultsAndFallback(t *testing.T) {
	for _, circuit := range []common.CircuitType{
		common.TransferConfidentialCircuitType, common.TransferRingCircuitType,
		common.TransferP256RingCircuitType, common.TransferRingAuthorityCircuitType,
		common.MergeCircuitType, common.MergeRingCircuitType,
		common.CustomRingBaseCircuitType, common.CustomRingPolicyCircuitType,
		common.BatchAddressAppendCircuitType,
	} {
		t.Run(string(circuit), func(t *testing.T) {
			transfer := isTransferCircuit(circuit)
			if got := useQueue(transfer, false, true, true); got == transfer {
				t.Fatalf("unexpected default queue selection for %s", circuit)
			}
			if !useQueue(transfer, true, true, true) {
				t.Fatal("explicit queue fallback was ignored")
			}
		})
	}
}
