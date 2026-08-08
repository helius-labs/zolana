package server

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"zolana/prover/logging"
	"zolana/prover/prover/common"
	mergeprover "zolana/prover/prover/merge"
	"zolana/prover/prover/nullifier_tree"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"
)

const (
	// JobExpirationTimeout must match the forester's max_wait_time.
	JobExpirationTimeout = 600 * time.Second

	// batchProofMemoryGB sizes the heaviest circuit, batch address-append.
	batchProofMemoryGB = 15

	// transferProofMemoryGB sizes a transfer proof, far lighter than a batch.
	transferProofMemoryGB = 2

	// hostMemoryReserveGB is headroom left for the OS. MemAvailable already
	// excludes the resident proving keys, so this covers only the rest.
	hostMemoryReserveGB = 4

	MinConcurrencyPerWorker = 1

	MaxConcurrencyPerWorker = 100
)

// workerConcurrency sizes one worker from cores and memory together. It starts
// no more proofs than the cores serve, nor more than availableGB holds at
// proofGB each. A Groth16 prove cannot be interrupted, so exceeding the memory
// budget is an OOM, not a queue. The light transfer worker lands core-bound,
// the heavy batch worker memory-bound, on one formula.
func workerConcurrency(proofGB, numCPU, availableGB int) int {
	n := numCPU
	if byMemory := availableGB / proofGB; byMemory < n {
		n = byMemory
	}
	if n < MinConcurrencyPerWorker {
		return MinConcurrencyPerWorker
	}
	if n > MaxConcurrencyPerWorker {
		return MaxConcurrencyPerWorker
	}
	return n
}

// budgetGB is the memory one worker may schedule into. PROVER_TOTAL_MEMORY_GB
// wins, else live MemAvailable, else zero which forces the minimum. The budget
// is per worker, so a host running both heavy workers at once must cap them
// with the env overrides.
func budgetGB() int {
	if val := os.Getenv("PROVER_TOTAL_MEMORY_GB"); val != "" {
		if totalMemGB, err := strconv.Atoi(val); err == nil && totalMemGB > 0 {
			return totalMemGB - hostMemoryReserveGB
		}
	}
	if avail := availableMemoryGB(); avail > 0 {
		return avail - hostMemoryReserveGB
	}
	return 0
}

// availableMemoryGB reads MemAvailable from /proc/meminfo. Zero means the
// platform does not expose it and the caller keeps the safe minimum.
func availableMemoryGB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0
		}
		return kb / (1024 * 1024)
	}
	return 0
}

// getMaxConcurrency sizes the batch address-append worker. PROVER_MAX_CONCURRENCY
// overrides.
func getMaxConcurrency() int {
	if val := os.Getenv("PROVER_MAX_CONCURRENCY"); val != "" {
		if concurrency, err := strconv.Atoi(val); err == nil && concurrency > 0 {
			logging.Logger().Info().
				Int("max_concurrency", concurrency).
				Msg("Using PROVER_MAX_CONCURRENCY")
			return concurrency
		}
	}
	concurrency := workerConcurrency(batchProofMemoryGB, runtime.NumCPU(), budgetGB())
	logging.Logger().Info().
		Int("max_concurrency", concurrency).
		Msg("Sized batch worker from cores and available memory (set PROVER_MAX_CONCURRENCY or PROVER_TOTAL_MEMORY_GB to override)")
	return concurrency
}

// getTransferMaxConcurrency sizes the transfer worker. A transfer proof is far
// lighter than a batch, so it lands core-bound on any real host.
// TRANSFER_WORKER_CONCURRENCY overrides.
func getTransferMaxConcurrency() int {
	if val := os.Getenv("TRANSFER_WORKER_CONCURRENCY"); val != "" {
		if concurrency, err := strconv.Atoi(val); err == nil && concurrency > 0 {
			logging.Logger().Info().
				Int("max_concurrency", concurrency).
				Msg("Using TRANSFER_WORKER_CONCURRENCY")
			return concurrency
		}
	}
	concurrency := workerConcurrency(transferProofMemoryGB, runtime.NumCPU(), budgetGB())
	logging.Logger().Info().
		Int("max_concurrency", concurrency).
		Msg("Sized transfer worker from cores and available memory (set TRANSFER_WORKER_CONCURRENCY to override)")
	return concurrency
}

type ProofJob struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
	// TreeID enables fair queuing across trees. Empty routes to the default queue.
	TreeID string `json:"tree_id,omitempty"`
	// BatchIndex orders batches within a tree. -1 means no batch index (FIFO).
	BatchIndex int64 `json:"batch_index"`
}

type QueueWorker interface {
	Start()
	Stop()
}

type BaseQueueWorker struct {
	queue               *RedisQueue
	keyManager          *common.LazyKeyManager
	stopChan            chan struct{}
	queueName           string
	processingQueueName string
	maxConcurrency      int
	semaphore           chan struct{}
}

type AddressAppendQueueWorker struct {
	*BaseQueueWorker
}

func NewAddressAppendQueueWorker(redisQueue *RedisQueue, keyManager *common.LazyKeyManager) *AddressAppendQueueWorker {
	maxConcurrency := getMaxConcurrency()
	return &AddressAppendQueueWorker{
		BaseQueueWorker: &BaseQueueWorker{
			queue:               redisQueue,
			keyManager:          keyManager,
			stopChan:            make(chan struct{}),
			queueName:           "zk_address_append_queue",
			processingQueueName: "zk_address_append_processing_queue",
			maxConcurrency:      maxConcurrency,
			semaphore:           make(chan struct{}, maxConcurrency),
		},
	}
}

func (w *BaseQueueWorker) Start() {
	logging.Logger().Info().
		Str("queue", w.queueName).
		Int("max_concurrency", w.maxConcurrency).
		Msg("Starting queue worker with parallel processing")

	for {
		select {
		case <-w.stopChan:
			logging.Logger().Info().Str("queue", w.queueName).Msg("Queue worker stopping")
			return
		default:
			w.processJobs()
		}
	}
}

func (w *BaseQueueWorker) Stop() {
	close(w.stopChan)
}

func (w *BaseQueueWorker) processJobs() {
	dequeueStart := time.Now()
	job, err := w.queue.DequeueProof(w.queueName, 5*time.Second)
	RecordDispatchStage(w.queueName, "dequeue", time.Since(dequeueStart))
	if err != nil {
		logging.Logger().Error().Err(err).Str("queue", w.queueName).Msg("Error dequeuing from queue")
		time.Sleep(2 * time.Second)
		return
	}

	if job == nil {
		time.Sleep(1 * time.Second)
		return
	}

	if !job.CreatedAt.IsZero() {
		jobAge := time.Since(job.CreatedAt)
		// Recorded before the expiry branch so expired jobs still count as wait.
		RecordQueueWait(w.queueName, jobAge)
		if jobAge > JobExpirationTimeout {
			logging.Logger().Warn().
				Str("job_id", job.ID).
				Str("job_type", job.Type).
				Str("queue", w.queueName).
				Dur("job_age", jobAge).
				Dur("expiration_timeout", JobExpirationTimeout).
				Time("created_at", job.CreatedAt).
				Msg("Skipping expired job - forester likely timed out")

			ExpiredJobsCounter.WithLabelValues(w.queueName).Inc()

			expirationErr := fmt.Errorf("job expired after %v (max: %v)", jobAge, JobExpirationTimeout)
			expiredInputHash := ComputeInputHash(job.Payload)
			w.addToFailedQueue(job, expiredInputHash, expirationErr)
			return
		}

		queueWaitTime := jobAge.Seconds()
		circuitType := "unknown"
		switch w.queueName {
		case "zk_address_append_queue":
			circuitType = "address-append"
		case "zk_transfer_queue":
			circuitType = "transfer"
		}
		QueueWaitTime.WithLabelValues(circuitType).Observe(queueWaitTime)
	}

	logging.Logger().Info().
		Str("job_id", job.ID).
		Str("job_type", job.Type).
		Str("queue", w.queueName).
		Msg("Dequeued proof job")

	// Everything from here to the semaphore runs on the loop that feeds every
	// worker. The dedup stage times it, cache-hit paths included.
	dedupStart := time.Now()
	inputHash := ComputeInputHash(job.Payload)

	cachedProof, cachedJobID, err := w.queue.FindCachedResult(inputHash)
	if err != nil {
		logging.Logger().Warn().
			Err(err).
			Str("job_id", job.ID).
			Str("input_hash", inputHash).
			Msg("Error searching for cached result, continuing with processing")
	} else if cachedProof != nil {
		logging.Logger().Info().
			Str("job_id", job.ID).
			Str("cached_job_id", cachedJobID).
			Str("input_hash", inputHash).
			Msg("Returning cached successful proof result without re-processing")

		resultData, _ := json.Marshal(cachedProof)
		resultJob := &ProofJob{
			ID:        job.ID,
			Type:      "result",
			Payload:   json.RawMessage(resultData),
			CreatedAt: time.Now(),
		}
		err = w.queue.EnqueueProof("zk_results_queue", resultJob)
		if err != nil {
			logging.Logger().Error().Err(err).Str("job_id", job.ID).Msg("Failed to enqueue cached result")
		}
		w.queue.StoreResult(job.ID, cachedProof)
		w.queue.StoreInputHash(job.ID, inputHash)
		w.queue.IndexResultByHash(inputHash, job.ID)
		RecordDispatchStage(w.queueName, "dedup", time.Since(dedupStart))
		return
	}

	cachedFailure, cachedFailedJobID, err := w.queue.FindCachedFailure(inputHash)
	if err != nil {
		logging.Logger().Warn().
			Err(err).
			Str("job_id", job.ID).
			Str("input_hash", inputHash).
			Msg("Error searching for cached failure, continuing with processing")
	} else if cachedFailure != nil {
		logging.Logger().Info().
			Str("job_id", job.ID).
			Str("cached_job_id", cachedFailedJobID).
			Str("input_hash", inputHash).
			Msg("Returning cached failure without re-processing")

		var errorMsg string
		if errMsg, ok := cachedFailure["error"].(string); ok {
			errorMsg = errMsg
		} else {
			errorMsg = "Proof generation failed (cached failure)"
		}

		// Omit the full payload to bound Redis memory.
		failedJob := map[string]interface{}{
			"original_job": map[string]interface{}{
				"id":           job.ID,
				"type":         job.Type,
				"payload_size": len(job.Payload),
				"created_at":   job.CreatedAt,
			},
			"error":       errorMsg,
			"failed_at":   time.Now(),
			"cached_from": cachedFailedJobID,
		}

		failedData, _ := json.Marshal(failedJob)
		failedJobStruct := &ProofJob{
			ID:        job.ID + "_failed",
			Type:      "failed",
			Payload:   json.RawMessage(failedData),
			CreatedAt: time.Now(),
		}

		err = w.queue.EnqueueProof("zk_failed_queue", failedJobStruct)
		if err != nil {
			logging.Logger().Error().Err(err).Str("job_id", job.ID).Msg("Failed to enqueue cached failure")
		}
		w.queue.StoreInputHash(job.ID, inputHash)
		w.queue.IndexFailureByHash(inputHash, job.ID)
		RecordDispatchStage(w.queueName, "dedup", time.Since(dedupStart))
		return
	}

	w.queue.StoreInputHash(job.ID, inputHash)
	RecordDispatchStage(w.queueName, "dedup", time.Since(dedupStart))

	// Blocking here means every worker is busy, the one healthy reason for the
	// loop to stall.
	semaphoreStart := time.Now()
	w.semaphore <- struct{}{}
	RecordDispatchStage(w.queueName, "semaphore", time.Since(semaphoreStart))

	go func(job *ProofJob, inputHash string) {
		defer func() {
			if r := recover(); r != nil {
				circuitType := "unknown"
				if meta, parseErr := common.ParseProofRequestMeta(job.Payload); parseErr != nil {
					logging.Logger().Warn().
						Err(parseErr).
						Str("job_id", job.ID).
						Msg("Failed to parse proof request meta while recovering panic")
				} else {
					circuitType = string(meta.CircuitType)
				}
				ProofPanicsTotal.WithLabelValues(circuitType).Inc()

				panicErr := fmt.Errorf("panic: %v", r)
				logging.Logger().Error().
					Interface("panic", r).
					Str("job_id", job.ID).
					Str("queue", w.queueName).
					Str("circuit_type", circuitType).
					Msg("Panic recovered in proof processing")

				w.removeFromProcessingQueue(job.ID)
				w.addToFailedQueue(job, inputHash, panicErr)

				if delErr := w.queue.DeleteInFlightJob(inputHash, job.ID); delErr != nil {
					logging.Logger().Warn().
						Err(delErr).
						Str("job_id", job.ID).
						Str("input_hash", inputHash).
						Msg("Failed to delete in-flight job marker (non-critical)")
				}
				if delErr := w.queue.DeleteJobMeta(job.ID); delErr != nil {
					logging.Logger().Warn().
						Err(delErr).
						Str("job_id", job.ID).
						Msg("Failed to delete job metadata (non-critical)")
				}
			}
			<-w.semaphore
		}()

		proofStartTime := time.Now()

		logging.Logger().Info().
			Str("job_id", job.ID).
			Str("queue", w.queueName).
			Msg("Starting proof generation")

		processingJob := &ProofJob{
			ID:        job.ID + "_processing",
			Type:      "processing",
			Payload:   job.Payload,
			CreatedAt: time.Now(),
		}
		err := w.queue.EnqueueProof(w.processingQueueName, processingJob)
		if err != nil {
			logging.Logger().Error().
				Err(err).
				Str("job_id", job.ID).
				Str("processing_queue", w.processingQueueName).
				Msg("Failed to add job to processing queue")
			return
		}

		proof, backend, err := w.generateProof(job)
		w.removeFromProcessingQueue(job.ID)

		proofDuration := time.Since(proofStartTime)

		if err != nil {
			logging.Logger().Error().
				Err(err).
				Str("job_id", job.ID).
				Str("queue", w.queueName).
				Dur("duration", proofDuration).
				Msg("Failed to process proof job")

			w.addToFailedQueue(job, inputHash, err)

			// Delete the in-flight marker so a new job can retry the same input.
			if delErr := w.queue.DeleteInFlightJob(inputHash, job.ID); delErr != nil {
				logging.Logger().Warn().
					Err(delErr).
					Str("job_id", job.ID).
					Str("input_hash", inputHash).
					Msg("Failed to delete in-flight job marker (non-critical)")
			}
			if delErr := w.queue.DeleteJobMeta(job.ID); delErr != nil {
				logging.Logger().Warn().
					Err(delErr).
					Str("job_id", job.ID).
					Msg("Failed to delete job metadata (non-critical)")
			}
		} else {
			proofWithTiming := &common.ProofWithTiming{
				Proof:           proof,
				ProofDurationMs: proofDuration.Milliseconds(),
				Backend:         backend,
			}

			resultData, _ := json.Marshal(proofWithTiming)
			resultJob := &ProofJob{
				ID:        job.ID,
				Type:      "result",
				Payload:   json.RawMessage(resultData),
				CreatedAt: time.Now(),
			}
			if enqueueErr := w.queue.EnqueueProof("zk_results_queue", resultJob); enqueueErr != nil {
				logging.Logger().Error().
					Err(enqueueErr).
					Str("job_id", job.ID).
					Msg("Failed to enqueue result")
			}
			if storeErr := w.queue.StoreResult(job.ID, proofWithTiming); storeErr != nil {
				logging.Logger().Error().
					Err(storeErr).
					Str("job_id", job.ID).
					Msg("Failed to store result")
			}

			if indexErr := w.queue.IndexResultByHash(inputHash, job.ID); indexErr != nil {
				logging.Logger().Warn().
					Err(indexErr).
					Str("job_id", job.ID).
					Msg("Failed to index result (non-critical)")
			}

			logging.Logger().Info().
				Str("job_id", job.ID).
				Str("queue", w.queueName).
				Dur("duration", proofDuration).
				Int64("duration_ms", proofDuration.Milliseconds()).
				Msg("Proof job completed successfully")

			// Keep the in-flight marker on success. It expires with the cached result on
			// the same TTL, so identical inputs reuse the result instead of creating a new
			// job.
			if delErr := w.queue.DeleteJobMeta(job.ID); delErr != nil {
				logging.Logger().Warn().
					Err(delErr).
					Str("job_id", job.ID).
					Msg("Failed to delete job metadata (non-critical)")
			}
		}
	}(job, inputHash)
}

func (w *AddressAppendQueueWorker) Start() {
	w.BaseQueueWorker.Start()
}

func (w *AddressAppendQueueWorker) Stop() {
	w.BaseQueueWorker.Stop()
}

// TransferQueueWorker drains the transfer/merge proof queue. Transfers are
// synchronous-fast individually but flood a shared prover under concurrency; the
// queue bounds in-flight proofs so many clients can submit without stampeding.
type TransferQueueWorker struct {
	*BaseQueueWorker
}

func NewTransferQueueWorker(redisQueue *RedisQueue, keyManager *common.LazyKeyManager) *TransferQueueWorker {
	maxConcurrency := getTransferMaxConcurrency()
	return &TransferQueueWorker{
		BaseQueueWorker: &BaseQueueWorker{
			queue:               redisQueue,
			keyManager:          keyManager,
			stopChan:            make(chan struct{}),
			queueName:           "zk_transfer_queue",
			processingQueueName: "zk_transfer_processing_queue",
			maxConcurrency:      maxConcurrency,
			semaphore:           make(chan struct{}, maxConcurrency),
		},
	}
}

func (w *TransferQueueWorker) Start() {
	w.BaseQueueWorker.Start()
}

func (w *TransferQueueWorker) Stop() {
	w.BaseQueueWorker.Stop()
}

// generateProof generates a proof for the given job and returns it with the
// backend that served it (empty on single-backend routes). Result storage is
// handled by the caller to include timing information.
func (w *BaseQueueWorker) generateProof(job *ProofJob) (*common.Proof, string, error) {
	proofRequestMeta, err := common.ParseProofRequestMeta(job.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse proof request: %w", err)
	}

	timer := StartProofTimer(string(proofRequestMeta.CircuitType))
	RecordCircuitInputSize(string(proofRequestMeta.CircuitType), len(job.Payload))

	var proof *common.Proof
	var backend string
	var proofError error

	switch proofRequestMeta.CircuitType {
	case common.BatchAddressAppendCircuitType:
		proof, proofError = w.processBatchAddressAppendProof(job.Payload)
	case common.TransferConfidentialCircuitType,
		common.TransferRingCircuitType,
		common.TransferRingAuthorityCircuitType:
		proof, proofError = w.processTransferEddsaProof(job.Payload)
	case common.TransferP256RingCircuitType:
		proof, proofError = w.processTransferP256Proof(job.Payload)
	case common.MergeCircuitType:
		proof, proofError = w.processMergeProof(job.Payload, common.MergeCircuitType)
	case common.MergeRingCircuitType:
		proof, proofError = w.processMergeProof(job.Payload, common.MergeRingCircuitType)
	default:
		return nil, "", fmt.Errorf("unknown circuit type: %s", proofRequestMeta.CircuitType)
	}

	if proofError != nil {
		timer.ObserveError("proof_generation_failed")
		RecordJobComplete(false)
		return nil, backend, proofError
	}

	timer.ObserveDuration()
	RecordJobComplete(true)

	if proof != nil {
		proofBytes, _ := json.Marshal(proof)
		RecordProofSize(string(proofRequestMeta.CircuitType), len(proofBytes))
	}

	return proof, backend, nil
}

func (w *BaseQueueWorker) processBatchAddressAppendProof(payload json.RawMessage) (*common.Proof, error) {
	var params nullifiertree.BatchAddressAppendParameters
	if err := json.Unmarshal(payload, &params); err != nil {
		return nil, fmt.Errorf("failed to unmarshal batch address append parameters: %w", err)
	}

	ps, err := w.keyManager.GetBatchSystem(
		common.BatchAddressAppendCircuitType,
		params.TreeHeight,
		params.BatchSize,
	)
	if err != nil {
		return nil, fmt.Errorf("batch address append proof: %w", err)
	}

	logging.Logger().Info().Msg("Processing batch address append proof")
	return nullifiertree.ProveBatchAddressAppend(ps, &params)
}

func (w *BaseQueueWorker) processTransferEddsaProof(payload json.RawMessage) (*common.Proof, error) {
	var params transfereddsaonly.TransferParameters
	if err := json.Unmarshal(payload, &params); err != nil {
		return nil, fmt.Errorf("unmarshal transfer-eddsa params: %w", err)
	}
	ps, err := w.keyManager.GetTransferSystem(params.Variant.CircuitType(), params.NInputs, params.NOutputs)
	if err != nil {
		return nil, fmt.Errorf("transfer-eddsa: %w", err)
	}
	return transfereddsaonly.ProveTransfer(ps, &params)
}

func (w *BaseQueueWorker) processTransferP256Proof(payload json.RawMessage) (*common.Proof, error) {
	var params transfereddsaonly.P256TransferParameters
	if err := json.Unmarshal(payload, &params); err != nil {
		return nil, fmt.Errorf("unmarshal transfer-p256 params: %w", err)
	}
	ps, err := w.keyManager.GetTransferSystem(
		common.TransferP256RingCircuitType,
		params.NInputs,
		params.NOutputs,
	)
	if err != nil {
		return nil, fmt.Errorf("transfer-p256: %w", err)
	}
	return transfereddsaonly.ProveP256Transfer(ps, &params)
}

func (w *BaseQueueWorker) processMergeProof(payload json.RawMessage, circuitType common.CircuitType) (*common.Proof, error) {
	var params mergeprover.MergeParameters
	if err := json.Unmarshal(payload, &params); err != nil {
		return nil, fmt.Errorf("unmarshal merge params: %w", err)
	}
	ps, err := w.keyManager.GetTransferSystem(circuitType, mergeprover.MergeNInputs, mergeprover.MergeNOutputs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", circuitType, err)
	}
	return mergeprover.ProveMerge(ps, &params)
}

func (w *BaseQueueWorker) removeFromProcessingQueue(jobID string) {
	processingQueueLength, _ := w.queue.Client.LLen(w.queue.Ctx, w.processingQueueName).Result()

	for i := range processingQueueLength {
		item, err := w.queue.Client.LIndex(w.queue.Ctx, w.processingQueueName, i).Result()
		if err != nil {
			continue
		}

		var job ProofJob
		if json.Unmarshal([]byte(item), &job) == nil && job.ID == jobID+"_processing" {
			w.queue.Client.LRem(w.queue.Ctx, w.processingQueueName, 1, item)
			break
		}
	}
}

func (w *BaseQueueWorker) addToFailedQueue(job *ProofJob, inputHash string, err error) {
	// Store the circuit type only. Full payloads would grow Redis without bound.
	var circuitType string
	var payloadMeta map[string]interface{}
	if json.Unmarshal(job.Payload, &payloadMeta) == nil {
		if ct, ok := payloadMeta["circuitType"].(string); ok {
			circuitType = ct
		}
	}

	failedJob := map[string]interface{}{
		"original_job": map[string]interface{}{
			"id":           job.ID,
			"type":         job.Type,
			"circuit_type": circuitType,
			"payload_size": len(job.Payload),
			"created_at":   job.CreatedAt,
		},
		"error":     err.Error(),
		"failed_at": time.Now(),
	}

	failedData, _ := json.Marshal(failedJob)
	failedJobStruct := &ProofJob{
		ID:        job.ID + "_failed",
		Type:      "failed",
		Payload:   json.RawMessage(failedData),
		CreatedAt: time.Now(),
	}

	enqueueErr := w.queue.EnqueueProof("zk_failed_queue", failedJobStruct)
	if enqueueErr != nil {
		logging.Logger().Error().
			Err(enqueueErr).
			Str("job_id", job.ID).
			Msg("Failed to add job to failed queue")
	}

	if inputHash != "" {
		if indexErr := w.queue.IndexFailureByHash(inputHash, job.ID); indexErr != nil {
			logging.Logger().Warn().
				Err(indexErr).
				Str("job_id", job.ID).
				Msg("Failed to index failure (non-critical)")
		}
	}
}
