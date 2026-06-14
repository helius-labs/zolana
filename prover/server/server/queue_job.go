package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
	"zolana/prover/logging"
	"zolana/prover/prover/common"
	"zolana/prover/prover/nullifier_tree"
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
	CreatedAt time.Time       `json:"created_at"`
	// TreeID is the merkle tree pubkey - used for fair queuing across trees
	// If empty, job goes to the default queue (backwards compatible)
	TreeID string `json:"tree_id,omitempty"`
	// BatchIndex is the batch sequence number within a tree - used to process batches in order
	// Lower batch indices should be processed first to enable sequential transaction submission
	// -1 means no batch index (legacy requests, FIFO)
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
	job, err := w.queue.DequeueProof(w.queueName, 5*time.Second)
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
			return
		}

		queueWaitTime := jobAge.Seconds()
		circuitType := "unknown"
		if w.queueName == "zk_address_append_queue" {
			circuitType = "address-append"
		}
		QueueWaitTime.WithLabelValues(circuitType).Observe(queueWaitTime)
	}

	logging.Logger().Info().
		Str("job_id", job.ID).
		Str("job_type", job.Type).
		Str("queue", w.queueName).
		Msg("Dequeued proof job")

	// Check for duplicate inputs before processing
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

		// Extract error message from cached failure
		var errorMsg string
		if errMsg, ok := cachedFailure["error"].(string); ok {
			errorMsg = errMsg
		} else {
			errorMsg = "Proof generation failed (cached failure)"
		}

		// Add to failed queue with new job ID (without full payload to save memory)
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
		return
	}

	// No cached result found, proceed with normal processing
	// Store the input hash for this job to enable future deduplication
	w.queue.StoreInputHash(job.ID, inputHash)

	w.semaphore <- struct{}{}

	go func(job *ProofJob, inputHash string) {
		defer func() {
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

		proof, err := w.generateProof(job)
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

			// On failure: clean up in-flight marker to allow retry with new job
			if delErr := w.queue.DeleteInFlightJob(inputHash, job.ID); delErr != nil {
				logging.Logger().Warn().
					Err(delErr).
					Str("job_id", job.ID).
					Str("input_hash", inputHash).
					Msg("Failed to delete in-flight job marker (non-critical)")
			}
			// Clean up job metadata
			if delErr := w.queue.DeleteJobMeta(job.ID); delErr != nil {
				logging.Logger().Warn().
					Err(delErr).
					Str("job_id", job.ID).
					Msg("Failed to delete job metadata (non-critical)")
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

// generateProof generates a proof for the given job and returns it.
// Result storage is handled by the caller to include timing information.
func (w *BaseQueueWorker) generateProof(job *ProofJob) (*common.Proof, error) {
	proofRequestMeta, err := common.ParseProofRequestMeta(job.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proof request: %w", err)
	}

	timer := StartProofTimer(string(proofRequestMeta.CircuitType))
	RecordCircuitInputSize(string(proofRequestMeta.CircuitType), len(job.Payload))

	var proof *common.Proof
	var proofError error

	log.Printf("proofRequestMeta.CircuitType: %s", proofRequestMeta.CircuitType)

	switch proofRequestMeta.CircuitType {
	case common.BatchAddressAppendCircuitType:
		proof, proofError = w.processBatchAddressAppendProof(job.Payload)
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
	// Extract circuit type from payload for debugging, but don't store full payload
	// to prevent memory issues (payloads can be hundreds of KB)
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
