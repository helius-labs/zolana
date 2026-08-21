package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
	"zolana/prover/logging"
	"zolana/prover/prover/common"
	customring "zolana/prover/prover/custom_ring"
	mergeprover "zolana/prover/prover/merge"
	"zolana/prover/prover/nullifier_tree"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"
)

const (
	// JobExpirationTimeout should match the forester's max_wait_time (600 seconds)
	JobExpirationTimeout = 600 * time.Second

	// Memory estimates per circuit type (in GB)
	// Based on live measurements: ~11GB per batch-500 proof
	// batch_update_32_500:        ~11GB (8M constraints)
	// batch_append_32_500:        ~11GB (7.8M constraints)
	// batch_address-append_40_250: ~15GB (larger tree height)
	//
	// For safety, we use the largest (address-append) as the baseline
	MemoryPerProofGB = 15

	// MemoryReserveGB is memory to reserve for OS, proving keys, and other processes
	// Proving keys can be 10-20GB depending on which circuits are loaded
	MemoryReserveGB = 20

	// NumQueueWorkers is the number of queue workers (update, append, address-append)
	NumQueueWorkers = 3

	// MinConcurrencyPerWorker is the minimum concurrency per worker
	MinConcurrencyPerWorker = 1

	// MaxConcurrencyPerWorker is the maximum concurrency per worker (safety cap)
	MaxConcurrencyPerWorker = 100
)

// getMaxConcurrency returns the max concurrency per worker.
// Configuration priority:
//  1. PROVER_MAX_CONCURRENCY env var
//  2. Auto-calculate from PROVER_TOTAL_MEMORY_GB env var
//  3. Default to MinConcurrencyPerWorker
func getMaxConcurrency() int {
	// Check for explicit concurrency override
	if val := os.Getenv("PROVER_MAX_CONCURRENCY"); val != "" {
		if concurrency, err := strconv.Atoi(val); err == nil && concurrency > 0 {
			logging.Logger().Info().
				Int("max_concurrency", concurrency).
				Msg("Using PROVER_MAX_CONCURRENCY")
			return concurrency
		}
	}

	// Check for memory-based configuration
	if val := os.Getenv("PROVER_TOTAL_MEMORY_GB"); val != "" {
		if totalMemGB, err := strconv.Atoi(val); err == nil && totalMemGB > 0 {
			concurrency := calculateConcurrency(totalMemGB)
			logging.Logger().Info().
				Int("total_memory_gb", totalMemGB).
				Int("max_concurrency", concurrency).
				Msg("Calculated concurrency from PROVER_TOTAL_MEMORY_GB")
			return concurrency
		}
	}

	// Default fallback
	logging.Logger().Info().
		Int("max_concurrency", MinConcurrencyPerWorker).
		Msg("Using default min concurrency (set PROVER_MAX_CONCURRENCY or PROVER_TOTAL_MEMORY_GB to configure)")
	return MinConcurrencyPerWorker
}

// getTransferMaxConcurrency returns how many transfer proofs the transfer worker
// runs at once. Transfer proofs are far lighter than batch address-append, so the
// operator can raise TRANSFER_WORKER_CONCURRENCY above the shared default (which
// getMaxConcurrency keeps conservative for the heavy batch worker).
func getTransferMaxConcurrency() int {
	if val := os.Getenv("TRANSFER_WORKER_CONCURRENCY"); val != "" {
		if concurrency, err := strconv.Atoi(val); err == nil && concurrency > 0 {
			logging.Logger().Info().
				Int("max_concurrency", concurrency).
				Msg("Using TRANSFER_WORKER_CONCURRENCY")
			return concurrency
		}
	}
	return getMaxConcurrency()
}

func getCustomRingAuditMaxConcurrency() int {
	if val := os.Getenv("CUSTOM_RING_AUDIT_WORKER_CONCURRENCY"); val != "" {
		if concurrency, err := strconv.Atoi(val); err == nil && concurrency > 0 {
			logging.Logger().Info().
				Int("max_concurrency", concurrency).
				Msg("Using CUSTOM_RING_AUDIT_WORKER_CONCURRENCY")
			return concurrency
		}
	}
	return getMaxConcurrency()
}

// calculateConcurrency computes per-worker concurrency from total memory.
// Formula: (TotalRAM - Reserve) / (MemoryPerProof * NumWorkers)
func calculateConcurrency(totalMemGB int) int {
	availableMemGB := totalMemGB - MemoryReserveGB
	if availableMemGB < MemoryPerProofGB {
		return MinConcurrencyPerWorker
	}

	totalConcurrentProofs := availableMemGB / MemoryPerProofGB
	perWorkerConcurrency := totalConcurrentProofs / NumQueueWorkers

	if perWorkerConcurrency < MinConcurrencyPerWorker {
		return MinConcurrencyPerWorker
	}
	if perWorkerConcurrency > MaxConcurrencyPerWorker {
		return MaxConcurrencyPerWorker
	}

	return perWorkerConcurrency
}

type ProofJob struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"createdAt"`
	// TreeID is the merkle tree pubkey - used for fair queuing across trees
	// If empty, job goes to the default queue (backwards compatible)
	TreeID string `json:"treeId,omitempty"`
	// BatchIndex is the batch sequence number within a tree - used to process batches in order
	// Lower batch indices should be processed first to enable sequential transaction submission
	// -1 means no batch index (legacy requests, FIFO)
	BatchIndex int64 `json:"batchIndex"`
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

type CustomRingAuditQueueWorker struct {
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

func NewCustomRingAuditQueueWorker(redisQueue *RedisQueue, keyManager *common.LazyKeyManager) *CustomRingAuditQueueWorker {
	maxConcurrency := getCustomRingAuditMaxConcurrency()
	return &CustomRingAuditQueueWorker{BaseQueueWorker: &BaseQueueWorker{
		queue:               redisQueue,
		keyManager:          keyManager,
		stopChan:            make(chan struct{}),
		queueName:           "zk_custom_ring_audit_queue",
		processingQueueName: "zk_custom_ring_audit_processing_queue",
		maxConcurrency:      maxConcurrency,
		semaphore:           make(chan struct{}, maxConcurrency),
	}}
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

	// Check if a job has expired
	if !job.CreatedAt.IsZero() {
		jobAge := time.Since(job.CreatedAt)
		// The same age answers a second question: how long the job waited to be
		// picked up. Recorded before the expiry branch so expired jobs, which
		// are the extreme case, still count.
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

			// Record metrics for expired jobs
			ExpiredJobsCounter.WithLabelValues(w.queueName).Inc()

			// Add to failed queue with expiration reason
			expirationErr := fmt.Errorf("job expired after %v (max: %v)", jobAge, JobExpirationTimeout)
			expiredInputHash := ComputeInputHash(job.Payload)
			w.addToFailedQueue(job, expiredInputHash, expirationErr)
			if metaErr := w.queue.MarkJobFailed(job.ID, w.failureDetails(job, expirationErr)); metaErr != nil {
				logging.Logger().Warn().
					Err(metaErr).
					Str("job_id", job.ID).
					Msg("Failed to record expiry in metadata")
			}
			return
		}

		queueWaitTime := jobAge.Seconds()
		circuitType := "unknown"
		switch w.queueName {
		case "zk_address_append_queue":
			circuitType = "address-append"
		case "zk_transfer_queue":
			circuitType = "transfer"
		case "zk_custom_ring_audit_queue":
			circuitType = "custom-ring-audit"
		}
		QueueWaitTime.WithLabelValues(circuitType).Observe(queueWaitTime)
	}

	logging.Logger().Info().
		Str("job_id", job.ID).
		Str("job_type", job.Type).
		Str("queue", w.queueName).
		Msg("Dequeued proof job")

	// Check for duplicate inputs before processing.
	//
	// Everything from here to the semaphore runs on the loop that feeds every
	// worker, so it is timed as "dedup": time spent here is admission rate lost,
	// including on the cache-hit paths that return without ever proving.
	dedupStart := time.Now()
	inputHash := ComputeInputHash(job.Payload)

	// Check if we already have a successful result for this input
	cachedProof, cachedJobID, err := w.queue.FindCachedResult(inputHash)
	if err != nil {
		logging.Logger().Warn().
			Err(err).
			Str("job_id", job.ID).
			Str("input_hash", inputHash).
			Msg("Error searching for cached result, continuing with processing")
	} else if cachedProof != nil {
		// Found a cached successful result, return it immediately
		logging.Logger().Info().
			Str("job_id", job.ID).
			Str("cached_job_id", cachedJobID).
			Str("input_hash", inputHash).
			Msg("Returning cached successful proof result without re-processing")

		// Store result for new job ID
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
		// Found a cached failure, return it immediately
		logging.Logger().Info().
			Str("job_id", job.ID).
			Str("cached_job_id", cachedFailedJobID).
			Str("input_hash", inputHash).
			Msg("Returning cached failure without re-processing")

		errorMsg := w.cachedFailureMessage(cachedFailure)

		// Add to failed queue with new job ID (without full payload to save memory)
		failedJob := map[string]interface{}{
			"originalJob": map[string]interface{}{
				"id":          job.ID,
				"type":        job.Type,
				"payloadSize": len(job.Payload),
				"createdAt":   job.CreatedAt,
			},
			"error":      errorMsg,
			"failedAt":   time.Now(),
			"cachedFrom": cachedFailedJobID,
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
		// A replayed failure is still terminal for this job id, so it has to be
		// visible to the status endpoint the same way a fresh one is.
		if metaErr := w.queue.MarkJobFailed(job.ID, failedJob); metaErr != nil {
			logging.Logger().Warn().
				Err(metaErr).
				Str("job_id", job.ID).
				Msg("Failed to record cached failure in metadata")
		}
		w.queue.StoreInputHash(job.ID, inputHash)
		w.queue.IndexFailureByHash(inputHash, job.ID)
		RecordDispatchStage(w.queueName, "dedup", time.Since(dedupStart))
		return
	}

	// No cached result found, proceed with normal processing
	// Store the input hash for this job to enable future deduplication
	w.queue.StoreInputHash(job.ID, inputHash)
	RecordDispatchStage(w.queueName, "dedup", time.Since(dedupStart))

	// Blocking here means every worker is busy, which is the one healthy reason
	// for the loop to stall. Separated from dedup so the two are never confused.
	semaphoreStart := time.Now()
	w.semaphore <- struct{}{}
	RecordDispatchStage(w.queueName, "semaphore", time.Since(semaphoreStart))

	go func(job *ProofJob, inputHash string) {
		// Set once the processing entry exists; the panic handler below reads
		// whatever it holds at that point, which is "" if we never got that far.
		var processingItem string
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

				panicErr := w.redactProofError(fmt.Errorf("panic: %v", r))
				logging.Logger().Error().
					Err(panicErr).
					Str("job_id", job.ID).
					Str("queue", w.queueName).
					Str("circuit_type", circuitType).
					Msg("Panic recovered in proof processing")

				w.removeFromProcessingQueue(processingItem)
				w.addToFailedQueue(job, inputHash, panicErr)

				if delErr := w.queue.DeleteInFlightJob(inputHash, job.ID); delErr != nil {
					logging.Logger().Warn().
						Err(delErr).
						Str("job_id", job.ID).
						Str("input_hash", inputHash).
						Msg("Failed to delete in-flight job marker (non-critical)")
				}
				// Keep the metadata and record why. Deleting it here left the
				// status endpoint with nothing to answer from, which is what
				// forced it to scan zk_failed_queue on every poll.
				if metaErr := w.queue.MarkJobFailed(job.ID, w.failureDetails(job, panicErr)); metaErr != nil {
					logging.Logger().Warn().
						Err(metaErr).
						Str("job_id", job.ID).
						Msg("Failed to record job failure in metadata")
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
		// Keep the stored bytes: they are the only handle LREM can match, and
		// searching for them later costs a round trip per queue entry.
		storedItem, err := w.queue.EnqueueProofReturning(w.processingQueueName, processingJob)
		if err != nil {
			logging.Logger().Error().
				Err(err).
				Str("job_id", job.ID).
				Str("processing_queue", w.processingQueueName).
				Msg("Failed to add job to processing queue")
			return
		}
		processingItem = storedItem
		if metaErr := w.queue.MarkJobProcessing(job.ID); metaErr != nil {
			logging.Logger().Warn().
				Err(metaErr).
				Str("job_id", job.ID).
				Msg("Failed to mark job processing (status polls will still report queued)")
		}

		proof, err := w.generateProof(job)
		w.removeFromProcessingQueue(processingItem)

		proofDuration := time.Since(proofStartTime)

		if err != nil {
			err = w.redactProofError(err)
			logging.Logger().Error().
				Err(err).
				Str("job_id", job.ID).
				Str("queue", w.queueName).
				Dur("duration", proofDuration).
				Msg("Failed to process proof job")

			w.addToFailedQueue(job, inputHash, err)

			// On failure: clean up in-flight marker to allow retry with new job
			if delErr := w.queue.DeleteInFlightJob(inputHash, job.ID); delErr != nil {
				logging.Logger().Warn().
					Err(delErr).
					Str("job_id", job.ID).
					Str("input_hash", inputHash).
					Msg("Failed to delete in-flight job marker (non-critical)")
			}
			// Record the failure in the metadata rather than dropping it: this
			// is the only record a polling client can be answered from once the
			// status endpoint stops scanning zk_failed_queue.
			if metaErr := w.queue.MarkJobFailed(job.ID, w.failureDetails(job, err)); metaErr != nil {
				logging.Logger().Warn().
					Err(metaErr).
					Str("job_id", job.ID).
					Msg("Failed to record job failure in metadata")
			}
		} else {
			// Store result with timing information
			proofWithTiming := &common.ProofWithTiming{
				Proof:           proof,
				ProofDurationMs: proofDuration.Milliseconds(),
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

			// On success: DON'T delete in-flight marker - let it expire with the result.
			// This allows future requests with identical inputs to get the cached result
			// instead of creating a new job. Both marker and result have 10-min TTL.
			// Only clean up job metadata (no longer needed since result is stored).
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

func (w *CustomRingAuditQueueWorker) Start() {
	w.BaseQueueWorker.Start()
}

func (w *CustomRingAuditQueueWorker) Stop() {
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

// generateProof generates a proof for the given job and returns it.
// Result storage is handled by the caller to include timing information.
func (w *BaseQueueWorker) generateProof(job *ProofJob) (*common.Proof, error) {
	proofRequestMeta, err := common.ParseProofRequestMeta(job.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proof request: %w", err)
	}
	if GetQueueNameForCircuit(proofRequestMeta.CircuitType) != w.queueName {
		return nil, fmt.Errorf("circuit %s cannot run on %s", proofRequestMeta.CircuitType, w.queueName)
	}

	timer := StartProofTimer(string(proofRequestMeta.CircuitType))
	RecordCircuitInputSize(string(proofRequestMeta.CircuitType), len(job.Payload))

	var proof *common.Proof
	var proofError error

	log.Printf("proofRequestMeta.CircuitType: %s", proofRequestMeta.CircuitType)

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
	case common.CustomRingAuditCircuitType:
		proof, proofError = w.processAuditorKeyEncryptionProof(job.Payload)
	default:
		return nil, fmt.Errorf("unknown circuit type: %s", proofRequestMeta.CircuitType)
	}

	if proofError != nil {
		timer.ObserveError("proof_generation_failed")
		RecordJobComplete(false)
		return nil, proofError
	}

	timer.ObserveDuration()
	RecordJobComplete(true)

	if proof != nil {
		proofBytes, _ := json.Marshal(proof)
		RecordProofSize(string(proofRequestMeta.CircuitType), len(proofBytes))
	}

	return proof, nil
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

func (w *BaseQueueWorker) processAuditorKeyEncryptionProof(payload json.RawMessage) (*common.Proof, error) {
	var params customring.AuditorKeyEncryptionParameters
	if err := json.Unmarshal(payload, &params); err != nil {
		return nil, fmt.Errorf("unmarshal auditor-key-encryption params: %w", err)
	}
	ps, err := w.keyManager.GetGroth16System(common.CustomRingAuditCircuitType, customring.TransferVariant)
	if err != nil {
		return nil, fmt.Errorf("auditor-key-encryption: %w", err)
	}
	return customring.ProveAuditorKeyEncryption(ps, &params)
}

// removeFromProcessingQueue drops the entry a worker added when it started, by
// value, in one command.
//
// It used to search: LLen, then an LINDEX round trip per position until the
// job id matched. That is O(queue length) *round trips* per completed proof,
// paid while holding a semaphore slot -- so the longer the processing queue
// grew, the longer each slot was held, the more work sat in flight, and the
// longer the queue grew. Measured on devnet at 220 workers: the processing
// queue climbed 210 -> 751 during one run when at most 128 proofs can actually
// be in flight, jobs waited 4.5-7s to be picked up behind a 108-deep pending
// queue, and the provers themselves sat at 12-33% CPU proving in 0.25s.
//
// The caller already holds the exact bytes it pushed, which is the only thing
// LREM can match on, so no search is needed.
func (w *BaseQueueWorker) removeFromProcessingQueue(item string) {
	if item == "" {
		return
	}
	if err := w.queue.Client.LRem(w.queue.Ctx, w.processingQueueName, 1, item).Err(); err != nil {
		logging.Logger().Warn().
			Err(err).
			Str("processing_queue", w.processingQueueName).
			Msg("Failed to remove entry from processing queue (cleanup will age it out)")
	}
}

var errCustomRingAuditProof = errors.New("custom ring audit proof failed")

func (w *BaseQueueWorker) redactProofError(err error) error {
	if w.queueName == "zk_custom_ring_audit_queue" {
		return errCustomRingAuditProof
	}
	return err
}

func (w *BaseQueueWorker) cachedFailureMessage(cachedFailure map[string]interface{}) string {
	errorMessage, ok := cachedFailure["error"].(string)
	if !ok {
		errorMessage = "Proof generation failed (cached failure)"
	}
	return w.redactProofError(errors.New(errorMessage)).Error()
}

// failureDetails describes a failed job for both the failed queue and the job
// metadata, so a caller sees the same thing wherever it is read from.
//
// The full payload is deliberately omitted -- payloads run to hundreds of KB,
// and this is stored once per failure on a path that already has memory
// pressure.
func (w *BaseQueueWorker) failureDetails(job *ProofJob, err error) map[string]interface{} {
	var circuitType string
	var payloadMeta map[string]interface{}
	if json.Unmarshal(job.Payload, &payloadMeta) == nil {
		if ct, ok := payloadMeta["circuitType"].(string); ok {
			circuitType = ct
		}
	}

	errorMessage := w.redactProofError(err).Error()

	return map[string]interface{}{
		"originalJob": map[string]interface{}{
			"id":          job.ID,
			"type":        job.Type,
			"circuitType": circuitType,
			"payloadSize": len(job.Payload),
			"createdAt":   job.CreatedAt,
		},
		"error":    errorMessage,
		"failedAt": time.Now(),
	}
}

func (w *BaseQueueWorker) addToFailedQueue(job *ProofJob, inputHash string, err error) {
	failedData, _ := json.Marshal(w.failureDetails(job, err))
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

	// Index the failure for O(1) cached lookups
	if inputHash != "" {
		if indexErr := w.queue.IndexFailureByHash(inputHash, job.ID); indexErr != nil {
			logging.Logger().Warn().
				Err(indexErr).
				Str("job_id", job.ID).
				Msg("Failed to index failure (non-critical)")
		}
	}
}
