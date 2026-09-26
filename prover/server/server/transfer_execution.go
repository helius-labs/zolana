package server

import (
	"sync"

	"zolana/prover/prover/common"
)

type Execution struct {
	admission *syncAdmission
}

func NewExecution(permits int) *Execution {
	return &Execution{admission: newSyncAdmission(permits)}
}

func (e *Execution) acquireQueued(stop <-chan struct{}) (func(), bool) {
	select {
	case <-stop:
		return nil, false
	default:
	}
	select {
	case e.admission.permits <- struct{}{}:
		return sync.OnceFunc(func() { <-e.admission.permits }), true
	case <-stop:
		return nil, false
	}
}

func isTransferCircuit(circuit common.CircuitType) bool {
	return GetQueueNameForCircuit(circuit) == "zk_transfer_queue"
}
