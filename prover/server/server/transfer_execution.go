package server

import (
	"os"
	"strconv"
	"sync"

	"zolana/prover/logging"
	"zolana/prover/prover/common"
	"zolana/prover/prover/indexed"
)

type TransferExecution struct {
	admission *syncAdmission
}

func NewTransferExecution() *TransferExecution {
	return &TransferExecution{admission: newSyncAdmission(transferConcurrency())}
}

func transferConcurrency() int {
	for _, name := range []string{"PROVER_TRANSFER_CONCURRENCY", "PROVER_SYNC_CONCURRENCY", "TRANSFER_WORKER_CONCURRENCY"} {
		if value := os.Getenv(name); value != "" {
			if count, err := strconv.Atoi(value); err == nil && count > 0 {
				return count
			}
			logging.Logger().Warn().Str("setting", name).Msg("Invalid transfer concurrency")
		}
	}
	return 1
}

func (e *TransferExecution) acquireQueued(stop <-chan struct{}) (func(), bool) {
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

type TransferWorkerConfig struct {
	Indexer   *indexed.Resolver
	Queue     *RedisQueue
	Keys      *common.LazyKeyManager
	Execution *TransferExecution
}
