package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"zolana/prover/logging"
	aggregateprover "zolana/prover/prover/aggregate"
	"zolana/prover/prover/common"
	keyencryption "zolana/prover/prover/key_encryption"
	mergeprover "zolana/prover/prover/merge"
	mergechainprover "zolana/prover/prover/merge_chain"
	nullifierfoldprover "zolana/prover/prover/nullifier_fold"
	nullifiertree "zolana/prover/prover/nullifier_tree"
	keyencryptionfold "zolana/prover/prover/squads_key_encryption_fold"
	squadsring "zolana/prover/prover/squads_ring"
	ringfold "zolana/prover/prover/squads_ring_fold"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type proofStatusHandler struct {
	redisQueue *RedisQueue
}

func (handler proofStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	jobID := r.URL.Query().Get("job_id")
	if jobID == "" {
		malformedBodyError(fmt.Errorf("job_id parameter required")).send(w)
		return
	}

	if !isValidJobID(jobID) {
		notFoundError := &Error{
			StatusCode: http.StatusBadRequest,
			Code:       "invalid_job_id",
			Message:    "Invalid job ID format. Job ID must be a valid UUID.",
		}
		notFoundError.send(w)
		return
	}

	logging.Logger().Info().
		Str("job_id", jobID).
		Msg("Checking job status")

	result, err := handler.redisQueue.GetResult(jobID)
	if err != nil && err != redis.Nil {
		logging.Logger().Error().
			Err(err).
			Str("job_id", jobID).
			Msg("Error retrieving result")
		unexpectedError(err).send(w)
		return
	}

	if err == nil && result != nil {
		logging.Logger().Info().
			Str("job_id", jobID).
			Msg("Job completed - returning result")

		response := map[string]interface{}{
			"job_id": jobID,
			"status": "completed",
			"result": result,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logging.Logger().Error().
				Err(err).
				Str("job_id", jobID).
				Str("response_type", "completed_result").
				Msg("Failed to encode JSON response")
		}
		return
	}

	jobExists, jobStatus, jobInfo := handler.checkJobExistsDetailed(jobID)

	if !jobExists {
		// Job metadata catches jobs submitted but not yet visible in queues due to Redis
		// replica lag or races.
		jobMeta, metaErr := handler.redisQueue.GetJobMeta(jobID)
		if metaErr != nil {
			logging.Logger().Warn().
				Err(metaErr).
				Str("job_id", jobID).
				Msg("Error checking job metadata")
		}

		if jobMeta != nil {
			logging.Logger().Info().
				Str("job_id", jobID).
				Interface("job_meta", jobMeta).
				Msg("Job not found in queues but metadata exists - returning queued status")

			response := map[string]interface{}{
				"job_id":  jobID,
				"status":  "queued",
				"message": "Job is queued and waiting to be processed",
			}
			if circuitType, ok := jobMeta["circuit_type"]; ok {
				response["circuit_type"] = circuitType
			}
			if submittedAt, ok := jobMeta["submitted_at"]; ok {
				response["submitted_at"] = submittedAt
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			if err := json.NewEncoder(w).Encode(response); err != nil {
				logging.Logger().Error().
					Err(err).
					Str("job_id", jobID).
					Str("response_type", "queued_status").
					Msg("Failed to encode JSON response")
			}
			return
		}

		logging.Logger().Warn().
			Str("job_id", jobID).
			Msg("Job not found in any queue or metadata")

		if handler.redisQueue != nil && handler.redisQueue.Client != nil {
			if stats, statsErr := handler.redisQueue.GetQueueStats(); statsErr == nil {
				logging.Logger().Info().
					Str("job_id", jobID).
					Interface("queue_stats", stats).
					Str("redis_addr", handler.redisQueue.Client.Options().Addr).
					Msg("Queue stats at job_not_found")
			} else {
				logging.Logger().Warn().
					Err(statsErr).
					Str("job_id", jobID).
					Msg("Failed to fetch queue stats during job_not_found")
			}
		}

		// A stale in-flight marker would block new jobs for the same input.
		handler.redisQueue.CleanupStaleInFlightMarker(jobID)

		notFoundError := &Error{
			StatusCode: http.StatusNotFound,
			Code:       "job_not_found",
			Message:    fmt.Sprintf("Job with ID %s not found. It may have expired or never existed.", jobID),
		}
		notFoundError.send(w)
		return
	}

	// Omit the payload to bound log size.
	logEvent := logging.Logger().Info().
		Str("job_id", jobID).
		Str("status", jobStatus)
	if jobInfo != nil {
		if ct, ok := jobInfo["circuit_type"]; ok {
			logEvent = logEvent.Interface("circuit_type", ct)
		}
		if ca, ok := jobInfo["created_at"]; ok {
			logEvent = logEvent.Interface("created_at", ca)
		}
	}
	logEvent.Msg("Job found but not completed")

	response := map[string]interface{}{
		"job_id": jobID,
		"status": jobStatus,
	}

	if jobStatus == "completed" && jobInfo != nil {
		if result, ok := jobInfo["result"]; ok {
			response["result"] = result
			logging.Logger().Info().
				Str("job_id", jobID).
				Msg("Returning result from checkJobExistsDetailed")
		}
	}

	if jobStatus == "failed" && jobInfo != nil {
		if payloadRaw, ok := jobInfo["payload"]; ok {
			if payloadStr, ok := payloadRaw.(string); ok {
				var failureDetails map[string]interface{}
				if err := json.Unmarshal([]byte(payloadStr), &failureDetails); err == nil {
					if errorMsg, ok := failureDetails["error"].(string); ok {
						response["message"] = fmt.Sprintf("Job processing failed: %s", errorMsg)
						response["error"] = errorMsg
					}
					if failedAt, ok := failureDetails["failed_at"]; ok {
						response["failed_at"] = failedAt
					}
					if originalJob, ok := failureDetails["original_job"].(map[string]interface{}); ok {
						if circuitType, ok := originalJob["circuit_type"]; ok {
							response["circuit_type"] = circuitType
						}
					}
				} else {
					response["message"] = "Job processing failed. Unable to parse failure details."
				}
			} else {
				response["message"] = "Job processing failed. Unable to access failure details."
			}
		} else {
			response["message"] = "Job processing failed. No failure details available."
		}
	} else {
		response["message"] = getStatusMessage(jobStatus)

		if jobInfo != nil {
			if createdAt, ok := jobInfo["created_at"]; ok {
				response["created_at"] = createdAt
			}
			if circuitType, ok := jobInfo["circuit_type"]; ok {
				response["circuit_type"] = circuitType
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")

	if jobStatus == "completed" {
		if _, hasResult := response["result"]; hasResult {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusAccepted)
		}
	} else {
		w.WriteHeader(http.StatusAccepted)
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

// proofWaitHandler blocks until the job finishes or the timeout passes, so a
// client gets its proof one round trip after completion instead of on its next
// poll. Timeout answers 202 and the client falls back to /prove/status, which
// also covers jobs whose reply already expired and job IDs that never existed.
type proofWaitHandler struct {
	redisQueue *RedisQueue
}

const (
	defaultWaitTimeout = 30 * time.Second
	// maxWaitTimeout stays below common load-balancer idle timeouts, so a
	// blocked wait is answered by this server and not severed upstream.
	maxWaitTimeout = 55 * time.Second
)

func (handler proofWaitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	jobID := r.URL.Query().Get("job_id")
	if jobID == "" {
		malformedBodyError(fmt.Errorf("job_id parameter required")).send(w)
		return
	}
	if !isValidJobID(jobID) {
		(&Error{
			StatusCode: http.StatusBadRequest,
			Code:       "invalid_job_id",
			Message:    "Invalid job ID format. Job ID must be a valid UUID.",
		}).send(w)
		return
	}

	timeout := defaultWaitTimeout
	if v := r.URL.Query().Get("timeout_s"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			malformedBodyError(fmt.Errorf("timeout_s must be a positive integer")).send(w)
			return
		}
		timeout = time.Duration(n) * time.Second
	}
	if timeout > maxWaitTimeout {
		timeout = maxWaitTimeout
	}

	// The result may already be stored, then no wait is needed and an expired
	// reply does not matter.
	if result, err := handler.redisQueue.GetResult(jobID); err == nil && result != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"job_id": jobID,
			"status": "completed",
			"result": result,
		})
		return
	}

	reply, err := handler.redisQueue.WaitReply(jobID, timeout)
	if err != nil {
		unexpectedError(err).send(w)
		return
	}
	if reply == nil {
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"job_id":  jobID,
			"status":  "pending",
			"message": "Job did not finish within the wait timeout. Poll /prove/status.",
		})
		return
	}

	RecordResultDelivered(reply.Queue, time.Since(reply.FinishedAt))

	if reply.Status == JobReplyFailed {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"job_id": jobID,
			"status": "failed",
			"error":  reply.Error,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"job_id": jobID,
		"status": "completed",
		"result": json.RawMessage(reply.Result),
	})
}

func writeJSON(w http.ResponseWriter, status int, body map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logging.Logger().Error().Err(err).Msg("Failed to encode JSON response")
	}
}

func isValidJobID(jobID string) bool {
	_, err := uuid.Parse(jobID)
	return err == nil
}

func getStatusMessage(status string) string {
	switch status {
	case "queued":
		return "Job is queued and waiting to be processed"
	case "processing":
		return "Job is currently being processed"
	case "failed":
		return "Job processing failed. Check the failed queue for details"
	case "completed":
		return "Job completed successfully"
	default:
		return "Job status unknown"
	}
}

func (handler proofStatusHandler) checkJobExistsDetailed(jobID string) (bool, string, map[string]interface{}) {
	result, err := handler.redisQueue.GetResult(jobID)
	if err == nil && result != nil {
		logging.Logger().Debug().
			Str("job_id", jobID).
			Msg("Job found in result cache")

		jobInfo := map[string]interface{}{
			"result":        result,
			"result_cached": true,
		}
		return true, "completed", jobInfo
	}

	// Metadata names the queue, so the search avoids a scan of every queue.
	jobMeta, metaErr := handler.redisQueue.GetJobMeta(jobID)
	if metaErr == nil && jobMeta != nil {
		if queueName, ok := jobMeta["queue"].(string); ok {
			if job, found := handler.findJobInQueue(queueName, jobID); found {
				return true, "queued", job
			}
			if len(queueName) >= 6 && strings.HasSuffix(queueName, "_queue") {
				base := queueName[:len(queueName)-6]
				processingQueue := base + "_processing_queue"
				if job, found := handler.findJobInQueue(processingQueue, jobID); found {
					return true, "processing", job
				}
			} else {
				logging.Logger().Warn().
					Str("job_id", jobID).
					Str("queue_name", queueName).
					Msg("Malformed queue name in job metadata - skipping processing queue check")
			}
		}
		if job, found := handler.findJobInQueue("zk_failed_queue", jobID); found {
			return true, "failed", job
		}
		if job, found := handler.findJobInQueue("zk_results_queue", jobID); found {
			handler.extractResultFromPayload(job)
			return true, "completed", job
		}
		// The job may have moved between queues mid-scan, so fall back to the metadata status.
		status := "queued"
		if metaStatus, ok := jobMeta["status"].(string); ok {
			status = metaStatus
		}
		return true, status, map[string]interface{}{
			"circuit_type": jobMeta["circuit_type"],
			"submitted_at": jobMeta["submitted_at"],
			"from_meta":    true,
		}
	}

	// Terminal states can outlive job metadata, so check the failed and results queues.
	if job, found := handler.findJobInQueue("zk_failed_queue", jobID); found {
		return true, "failed", job
	}

	if job, found := handler.findJobInQueue("zk_results_queue", jobID); found {
		handler.extractResultFromPayload(job)
		return true, "completed", job
	}

	return false, "", nil
}

func (handler proofStatusHandler) extractResultFromPayload(job map[string]interface{}) {
	if payloadRaw, ok := job["payload"]; ok {
		if payloadStr, ok := payloadRaw.(string); ok {
			var payloadData map[string]interface{}
			if json.Unmarshal([]byte(payloadStr), &payloadData) == nil {
				job["result"] = payloadData
			}
		}
	}
}

func (handler proofStatusHandler) findJobInQueue(queueName, jobID string) (map[string]interface{}, bool) {
	items, err := handler.redisQueue.Client.LRange(handler.redisQueue.Ctx, queueName, 0, -1).Result()
	if err != nil {
		logging.Logger().Error().
			Err(err).
			Str("queue", queueName).
			Str("job_id", jobID).
			Msg("Error searching queue")
		return nil, false
	}

	for _, item := range items {
		var job ProofJob
		if json.Unmarshal([]byte(item), &job) == nil {
			if job.ID == jobID ||
				job.ID == jobID+"_processing" ||
				job.ID == jobID+"_failed" {

				jobInfo := map[string]interface{}{
					"created_at": job.CreatedAt,
				}

				if len(job.Payload) > 0 {
					jobInfo["payload"] = string(job.Payload)

					var meta map[string]interface{}
					if json.Unmarshal(job.Payload, &meta) == nil {
						if circuitType, ok := meta["circuit_type"]; ok {
							jobInfo["circuit_type"] = circuitType
						}
					}
				}

				logging.Logger().Info().
					Str("job_id", jobID).
					Str("queue", queueName).
					Str("found_job_id", job.ID).
					Msg("Job found in queue")

				return jobInfo, true
			}
		}
	}

	return nil, false
}

type QueueConfig struct {
	RedisURL string
	Enabled  bool
}

type EnhancedConfig struct {
	ProverAddress       string
	MetricsAddress      string
	MaxRequestBodyBytes int64
	Queue               *QueueConfig
}

type proveHandler struct {
	keyManager          *common.LazyKeyManager
	redisQueue          *RedisQueue
	enableQueue         bool
	maxRequestBodyBytes int64
}

func (handler proveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	buf, requestError := readRequestBody(w, r, handler.maxRequestBodyBytes)
	if requestError != nil {
		requestError.send(w)
		return
	}

	proofRequestMeta, err := common.ParseProofRequestMeta(buf)
	if err != nil {
		malformedBodyError(err).send(w)
		return
	}

	forceAsync := r.Header.Get("X-Async") == "true" || r.URL.Query().Get("async") == "true"
	forceSync := r.Header.Get("X-Sync") == "true" || r.URL.Query().Get("sync") == "true"

	shouldUseQueue := handler.shouldUseQueueForCircuit(proofRequestMeta.CircuitType)

	logging.Logger().Info().
		Str("circuit_type", string(proofRequestMeta.CircuitType)).
		Bool("force_async", forceAsync).
		Bool("force_sync", forceSync).
		Bool("use_queue", shouldUseQueue).
		Bool("queue_available", handler.enableQueue && handler.redisQueue != nil).
		Msg("Processing prove request")

	// Counted here because every request passes this point exactly once.
	// A count inside the handlers doubles the queued path.
	ProofRequestsTotal.WithLabelValues(string(proofRequestMeta.CircuitType)).Inc()
	RecordCircuitInputSize(string(proofRequestMeta.CircuitType), len(buf))

	if shouldUseQueue && handler.enableQueue && handler.redisQueue != nil {
		handler.handleAsyncProof(w, r, buf, proofRequestMeta)
	} else {
		handler.handleSyncProof(w, r, buf, proofRequestMeta)
	}
}

func (handler proveHandler) shouldUseQueueForCircuit(circuitType common.CircuitType) bool {
	if !handler.enableQueue || handler.redisQueue == nil {
		return false
	}

	return GetQueueNameForCircuit(circuitType) != ""
}

type queueStatsHandler struct {
	redisQueue *RedisQueue
}

func (handler queueStatsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	stats, err := handler.redisQueue.GetQueueStats()
	if err != nil {
		unexpectedError(err).send(w)
		return
	}

	response := map[string]interface{}{
		"queues":        stats,
		"total_pending": stats["zk_address_append_queue"] + stats["zk_transfer_queue"],
		"total_active":  stats["zk_address_append_processing_queue"] + stats["zk_transfer_processing_queue"],
		"total_failed":  stats["zk_failed_queue"],
		"timestamp":     time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

type queueHealthHandler struct {
	redisQueue *RedisQueue
}

func (handler queueHealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	health, err := handler.redisQueue.GetQueueHealth()
	if err != nil {
		unexpectedError(err).send(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(health)
	if err != nil {
		return
	}
}

type queueCleanupHandler struct {
	redisQueue *RedisQueue
}

func (handler queueCleanupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	results := make(map[string]interface{})

	if err := handler.redisQueue.CleanupOldRequests(); err != nil {
		results["old_requests_cleanup"] = map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	} else {
		results["old_requests_cleanup"] = map[string]interface{}{
			"success": true,
		}
	}

	if err := handler.redisQueue.CleanupStuckProcessingJobs(); err != nil {
		results["stuck_jobs_cleanup"] = map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	} else {
		results["stuck_jobs_cleanup"] = map[string]interface{}{
			"success": true,
		}
	}

	if err := handler.redisQueue.CleanupOldFailedJobs(); err != nil {
		results["old_failed_cleanup"] = map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	} else {
		results["old_failed_cleanup"] = map[string]interface{}{
			"success": true,
		}
	}

	if err := handler.redisQueue.CleanupOldResultKeys(); err != nil {
		results["old_result_keys_cleanup"] = map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	} else {
		results["old_result_keys_cleanup"] = map[string]interface{}{
			"success": true,
		}
	}

	results["timestamp"] = time.Now().Unix()

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(results)
	if err != nil {
		return
	}
}

func RunWithQueue(config *Config, redisQueue *RedisQueue, keyManager *common.LazyKeyManager) RunningJob {
	return RunEnhanced(&EnhancedConfig{
		ProverAddress:       config.ProverAddress,
		MetricsAddress:      config.MetricsAddress,
		MaxRequestBodyBytes: config.MaxRequestBodyBytes,
		Queue: &QueueConfig{
			Enabled: redisQueue != nil,
		},
	}, redisQueue, keyManager)
}

func RunEnhanced(config *EnhancedConfig, redisQueue *RedisQueue, keyManager *common.LazyKeyManager) RunningJob {
	maxRequestBodyBytes := config.MaxRequestBodyBytes
	if maxRequestBodyBytes <= 0 {
		maxRequestBodyBytes = DefaultMaxRequestBodyBytes
	}

	apiKey := getAPIKeyFromEnv()
	requireConfiguredKey := !isLoopbackBindAddress(config.ProverAddress)
	if apiKey != "" {
		logging.Logger().Info().Msg("API key authentication enabled for prover server")
	} else if requireConfiguredKey {
		logging.Logger().Error().Msg("ZOLANA_PROVER_API_KEY or PROVER_API_KEY is required because the prover listens beyond localhost; protected endpoints will reject requests")
	} else {
		logging.Logger().Warn().Msg("No API key configured; prover endpoints are available only through the loopback listener")
	}
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsServer := newHTTPServer(config.MetricsAddress, metricsMux)
	metricsJob := spawnServerJob(metricsServer, "metrics server")
	logging.Logger().Info().Str("addr", config.MetricsAddress).Msg("metrics server started")

	proverMux := http.NewServeMux()

	proverMux.Handle("/prove", proveHandler{
		keyManager:          keyManager,
		redisQueue:          redisQueue,
		enableQueue:         config.Queue != nil && config.Queue.Enabled,
		maxRequestBodyBytes: maxRequestBodyBytes,
	})

	proverMux.Handle("/health", healthHandler{})

	if redisQueue != nil {
		proverMux.Handle("/prove/status", proofStatusHandler{redisQueue: redisQueue})
		proverMux.Handle("/prove/wait", proofWaitHandler{redisQueue: redisQueue})
		proverMux.Handle("/queue/stats", queueStatsHandler{redisQueue: redisQueue})
		proverMux.Handle("/queue/health", queueHealthHandler{redisQueue: redisQueue})
		proverMux.Handle("/queue/cleanup", queueCleanupHandler{redisQueue: redisQueue})

		proverMux.HandleFunc("/queue/add", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			buf, requestError := readRequestBody(w, r, maxRequestBodyBytes)
			if requestError != nil {
				requestError.send(w)
				return
			}

			proofRequestMeta, err := common.ParseProofRequestMeta(buf)
			if err != nil {
				malformedBodyError(err).send(w)
				return
			}

			queueName := GetQueueNameForCircuit(proofRequestMeta.CircuitType)
			if queueName == "" {
				(&Error{
					StatusCode: http.StatusBadRequest,
					Code:       "circuit_not_queueable",
					Message:    fmt.Sprintf("circuit %s cannot be persisted in the proof queue", proofRequestMeta.CircuitType),
				}).send(w)
				return
			}

			inputHash := ComputeInputHash(json.RawMessage(buf))

			dedupResult, err := redisQueue.DeduplicateJob(inputHash)
			if err != nil {
				logging.Logger().Error().
					Err(err).
					Str("input_hash", inputHash).
					Msg("Failed to deduplicate job")
				http.Error(w, "Failed to register job", http.StatusInternalServerError)
				return
			}

			if dedupResult.IsDeduplicated {
				response := map[string]interface{}{
					"job_id":       dedupResult.JobID,
					"status":       "already_queued",
					"queue":        queueName,
					"circuit_type": string(proofRequestMeta.CircuitType),
					"message":      "Proof request with identical input already in queue. Returning existing job ID.",
					"deduplicated": true,
				}

				logging.Logger().Info().
					Str("existing_job_id", dedupResult.JobID).
					Str("input_hash", inputHash).
					Str("circuit_type", string(proofRequestMeta.CircuitType)).
					Msg("Deduplicated proof request via /queue/add")

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				if err := json.NewEncoder(w).Encode(response); err != nil {
					logging.Logger().Error().
						Err(err).
						Str("job_id", dedupResult.JobID).
						Str("response_type", "deduplicated_queue_add_response").
						Msg("Failed to encode JSON response")
				}
				return
			}

			jobID := dedupResult.JobID

			job := &ProofJob{
				ID:         jobID,
				Type:       "zk_proof",
				Payload:    json.RawMessage(buf),
				CreatedAt:  time.Now(),
				TreeID:     proofRequestMeta.TreeID,
				BatchIndex: proofRequestMeta.BatchIndex,
			}

			// Store job metadata BEFORE enqueueing to prevent race condition where worker
			// picks up job before metadata exists, causing job_not_found on status checks
			if err := redisQueue.StoreJobMeta(jobID, queueName, string(proofRequestMeta.CircuitType)); err != nil {
				logging.Logger().Warn().
					Err(err).
					Str("job_id", jobID).
					Str("queue", queueName).
					Msg("Failed to store job metadata (will still attempt to enqueue)")
			}

			redisQueue.StoreInputHash(jobID, inputHash)

			err = redisQueue.EnqueueProof(queueName, job)
			if err != nil {
				if delErr := redisQueue.DeleteInFlightJob(inputHash, jobID); delErr != nil {
					logging.Logger().Error().Err(delErr).Str("job_id", jobID).Msg("Failed to cleanup in-flight marker after enqueue failure - may cause stale deduplication")
				}
				if delErr := redisQueue.DeleteJobMeta(jobID); delErr != nil {
					logging.Logger().Error().Err(delErr).Str("job_id", jobID).Msg("Failed to cleanup job metadata after enqueue failure")
				}
				unexpectedError(err).send(w)
				return
			}

			logging.Logger().Info().
				Str("job_id", jobID).
				Str("queue", queueName).
				Str("circuit_type", string(proofRequestMeta.CircuitType)).
				Msg("Enqueued proof job")

			response := map[string]interface{}{
				"job_id":       jobID,
				"status":       "queued",
				"queue":        queueName,
				"circuit_type": string(proofRequestMeta.CircuitType),
				"message":      fmt.Sprintf("Job queued in %s", queueName),
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			err = json.NewEncoder(w).Encode(response)
			if err != nil {
				return
			}
		})
	}

	proverServer := newHTTPServer(config.ProverAddress, proverHandlerChain(apiKey, requireConfiguredKey, proverMux))
	proverJob := spawnServerJob(proverServer, "prover server")

	if redisQueue != nil {
		logging.Logger().Info().
			Str("addr", config.ProverAddress).
			Bool("queue_enabled", true).
			Msg("enhanced prover server started with Redis queue support")
	} else {
		logging.Logger().Info().
			Str("addr", config.ProverAddress).
			Bool("queue_enabled", false).
			Msg("prover server started (no queue support)")
	}

	return CombineJobs(metricsJob, proverJob)
}

// proverHandlerChain puts authentication outside CORS. The CORS handler answers
// a preflight on its own, so an outer CORS handler would serve it before any
// credential is checked.
func proverHandlerChain(apiKey string, requireConfiguredKey bool, next http.Handler) http.Handler {
	corsHandler := handlers.CORS(
		handlers.AllowedHeaders([]string{
			"X-Requested-With",
			"Content-Type",
			"Authorization",
			"X-API-Key",
			"X-Async",
			"X-Sync",
		}),
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
	)

	return conditionalAuthMiddleware(apiKey, requireConfiguredKey)(corsHandler(next))
}

func Run(config *Config, keyManager *common.LazyKeyManager) RunningJob {
	return RunWithQueue(config, nil, keyManager)
}

type Error struct {
	StatusCode int
	Code       string
	Message    string
}

func malformedBodyError(err error) *Error {
	return &Error{StatusCode: http.StatusBadRequest, Code: "malformed_body", Message: err.Error()}
}

func requestBodyTooLargeError(maxBytes int64) *Error {
	return &Error{
		StatusCode: http.StatusRequestEntityTooLarge,
		Code:       "request_too_large",
		Message:    fmt.Sprintf("request body exceeds the %d byte limit", maxBytes),
	}
}

func provingError(err error) *Error {
	return &Error{StatusCode: http.StatusBadRequest, Code: "proving_error", Message: err.Error()}
}

func unexpectedError(err error) *Error {
	return &Error{StatusCode: http.StatusInternalServerError, Code: "unexpected_error", Message: err.Error()}
}

func requestAbandonedError(err error) *Error {
	return &Error{StatusCode: http.StatusRequestTimeout, Code: "request_abandoned", Message: err.Error()}
}

func (error *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"code":    error.Code,
		"message": error.Message,
	})
}

func (error *Error) send(w http.ResponseWriter) {
	w.WriteHeader(error.StatusCode)
	jsonBytes, err := error.MarshalJSON()
	if err != nil {
		jsonBytes = []byte(`{"code": "unexpected_error", "message": "failed to marshal error"}`)
	}
	length, err := w.Write(jsonBytes)
	if err != nil || length != len(jsonBytes) {
		logging.Logger().Error().Err(err).Msg("error writing response")
	}
}

type Config struct {
	ProverAddress       string
	MetricsAddress      string
	MaxRequestBodyBytes int64
}

const (
	DefaultMaxRequestBodyBytes = int64(16 << 20)
	defaultMaxHeaderBytes      = 64 << 10
	defaultReadHeaderTimeout   = 10 * time.Second
	defaultReadTimeout         = 30 * time.Second
	defaultIdleTimeout         = 2 * time.Minute
	// defaultWriteTimeout must stay above maxSyncProofTimeout. The deadline
	// covers the whole exchange after the request headers, so a shorter one
	// severs the connection of a proof that is still allowed to run.
	defaultWriteTimeout = maxSyncProofTimeout + time.Minute
)

func readRequestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, *Error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxRequestBodyBytes
	}

	buf, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err == nil {
		return buf, nil
	}

	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return nil, requestBodyTooLargeError(maxBytes)
	}
	return nil, malformedBodyError(err)
}

func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
	}
}

func spawnServerJob(server *http.Server, label string) RunningJob {
	start := func() {
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("%s failed: %s", label, err))
		}
	}
	shutdown := func() {
		logging.Logger().Info().Msgf("shutting down %s", label)
		err := server.Shutdown(context.Background())
		if err != nil {
			logging.Logger().Error().Err(err).Msgf("error when shutting down %s", label)
		}
		logging.Logger().Info().Msgf("%s shut down", label)
	}
	return SpawnJob(start, shutdown)
}

type healthHandler struct {
}

func (handler proveHandler) handleAsyncProof(w http.ResponseWriter, r *http.Request, buf []byte, meta common.ProofRequestMeta) {
	queueName := GetQueueNameForCircuit(meta.CircuitType)

	inputHash := ComputeInputHash(json.RawMessage(buf))

	dedupResult, err := handler.redisQueue.DeduplicateJob(inputHash)
	if err != nil {
		logging.Logger().Error().
			Err(err).
			Str("input_hash", inputHash).
			Msg("Failed to deduplicate job")
		http.Error(w, "Failed to register job", http.StatusInternalServerError)
		return
	}

	if dedupResult.IsDeduplicated {
		response := map[string]interface{}{
			"job_id":       dedupResult.JobID,
			"status":       "already_queued",
			"circuit_type": string(meta.CircuitType),
			"queue":        queueName,
			"message":      "Proof request with identical input already in queue. Returning existing job ID.",
			"deduplicated": true,
		}

		logging.Logger().Info().
			Str("existing_job_id", dedupResult.JobID).
			Str("input_hash", inputHash).
			Str("circuit_type", string(meta.CircuitType)).
			Msg("Deduplicated proof request - returning existing job")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logging.Logger().Error().
				Err(err).
				Str("job_id", dedupResult.JobID).
				Str("response_type", "deduplicated_async_response").
				Msg("Failed to encode JSON response")
		}
		return
	}

	jobID := dedupResult.JobID

	job := &ProofJob{
		ID:         jobID,
		Type:       "zk_proof",
		Payload:    json.RawMessage(buf),
		CreatedAt:  time.Now(),
		TreeID:     meta.TreeID,
		BatchIndex: meta.BatchIndex,
	}

	// Store job metadata BEFORE enqueueing to prevent race condition where worker
	// picks up job before metadata exists, causing job_not_found on status checks
	if err := handler.redisQueue.StoreJobMeta(jobID, queueName, string(meta.CircuitType)); err != nil {
		logging.Logger().Warn().
			Err(err).
			Str("job_id", jobID).
			Str("queue", queueName).
			Msg("Failed to store job metadata (will still attempt to enqueue)")
	}

	handler.redisQueue.StoreInputHash(jobID, inputHash)

	err = handler.redisQueue.EnqueueProof(queueName, job)
	if err != nil {
		logging.Logger().Error().Err(err).Msg("Failed to enqueue proof job")

		if delErr := handler.redisQueue.DeleteInFlightJob(inputHash, jobID); delErr != nil {
			logging.Logger().Error().Err(delErr).Str("job_id", jobID).Msg("Failed to cleanup in-flight marker after enqueue failure - may cause stale deduplication")
		}
		if delErr := handler.redisQueue.DeleteJobMeta(jobID); delErr != nil {
			logging.Logger().Error().Err(delErr).Str("job_id", jobID).Msg("Failed to cleanup job metadata after enqueue failure")
		}

		if handler.isBatchOperation(meta.CircuitType) {
			serviceUnavailableError := &Error{
				StatusCode: http.StatusServiceUnavailable,
				Code:       "queue_unavailable",
				Message:    fmt.Sprintf("Queue service unavailable and %s requires asynchronous processing", meta.CircuitType),
			}
			serviceUnavailableError.send(w)
			return
		}

		logging.Logger().Warn().Msg("Queue failed, falling back to synchronous processing")
		handler.handleSyncProof(w, r, buf, meta)
		return
	}

	estimatedTime := handler.getEstimatedTime(meta.CircuitType)

	response := map[string]interface{}{
		"job_id":         jobID,
		"status":         "queued",
		"circuit_type":   string(meta.CircuitType),
		"queue":          queueName,
		"estimated_time": estimatedTime,
		"status_url":     fmt.Sprintf("/prove/status?job_id=%s", jobID),
		"message":        fmt.Sprintf("Proof generation queued for %s circuit. Use status_url to check progress.", meta.CircuitType),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}

	logging.Logger().Info().
		Str("job_id", jobID).
		Str("queue", queueName).
		Str("circuit_type", string(meta.CircuitType)).
		Msg("Batch operation job queued successfully")
}

const (
	minSyncProofTimeout = 10 * time.Second
	maxSyncProofTimeout = 300 * time.Second
)

// syncProofSlots bounds the proofs the synchronous path starts, the way the
// queue workers bound theirs. Each prove holds a proving key and its witness,
// so an unbounded request count exhausts memory long before it saturates the
// cores.
var syncProofSlots = sync.OnceValue(func() chan struct{} {
	slots := getMaxConcurrency()
	logging.Logger().Info().
		Int("max_concurrency", slots).
		Msg("Bounding synchronous proofs")
	return make(chan struct{}, slots)
})

func (handler proveHandler) handleSyncProof(w http.ResponseWriter, r *http.Request, buf []byte, meta common.ProofRequestMeta) {
	if handler.isBatchOperation(meta.CircuitType) {
		warning := fmt.Sprintf("WARNING: %s is a heavy operation that should be processed asynchronously. Consider using X-Async: true header.", meta.CircuitType)
		w.Header().Set("X-Warning", warning)
		logging.Logger().Warn().
			Str("circuit_type", string(meta.CircuitType)).
			Msg("Processing batch operation synchronously - this may cause timeouts")
	}

	estimatedTime := handler.getEstimatedTimeSeconds(meta.CircuitType)
	timeoutDuration := time.Duration(estimatedTime*2) * time.Second
	if timeoutDuration < minSyncProofTimeout {
		timeoutDuration = minSyncProofTimeout
	}
	if timeoutDuration > maxSyncProofTimeout {
		timeoutDuration = maxSyncProofTimeout
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeoutDuration)
	defer cancel()

	slots := syncProofSlots()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		(&Error{
			StatusCode: http.StatusServiceUnavailable,
			Code:       "prover_busy",
			Message:    "Every prover slot is taken. Retry, or use asynchronous mode with the X-Async: true header.",
		}).send(w)
		logging.Logger().Warn().
			Str("circuit_type", string(meta.CircuitType)).
			Msg("Synchronous proof gave up waiting for a prover slot")
		return
	}

	type proofResult struct {
		proof *common.Proof
		err   *Error
	}

	resultChan := make(chan proofResult, 1)

	go func() {
		defer func() { <-slots }()
		defer func() {
			if r := recover(); r != nil {
				ProofPanicsTotal.WithLabelValues(string(meta.CircuitType)).Inc()
				logging.Logger().Error().
					Interface("panic", r).
					Str("circuit_type", string(meta.CircuitType)).
					Msg("Panic recovered in proof processing")
				resultChan <- proofResult{
					proof: nil,
					err:   unexpectedError(fmt.Errorf("internal error during proof processing: %v", r)),
				}
			}
		}()

		timer := StartProofTimer(string(meta.CircuitType))

		proof, proofError := handler.processProofSync(ctx, buf)

		if proofError != nil {
			timer.ObserveError(proofError.Code)
			RecordJobComplete(false)
		} else {
			timer.ObserveDuration()
			RecordJobComplete(true)
			if proof != nil {
				if proofBytes, marshalErr := json.Marshal(proof); marshalErr == nil {
					RecordProofSize(string(meta.CircuitType), len(proofBytes))
				}
			}
		}

		resultChan <- proofResult{proof: proof, err: proofError}
	}()

	select {
	case result := <-resultChan:
		if result.err != nil {
			result.err.send(w)
			return
		}

		responseBytes, err := json.Marshal(result.proof)
		if err != nil {
			unexpectedError(err).send(w)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(responseBytes)
		if err != nil {
			return
		}

		logging.Logger().Info().
			Str("circuit_type", string(meta.CircuitType)).
			Msg("Synchronous proof completed successfully")

	case <-ctx.Done():
		timeoutError := &Error{
			StatusCode: http.StatusRequestTimeout,
			Code:       "proof_timeout",
			Message:    fmt.Sprintf("Proof generation timed out after %d seconds. For %s circuits, use asynchronous mode with X-Async: true header.", int(timeoutDuration.Seconds()), meta.CircuitType),
		}
		timeoutError.send(w)

		logging.Logger().Warn().
			Str("circuit_type", string(meta.CircuitType)).
			Int("timeout_seconds", int(timeoutDuration.Seconds())).
			Msg("Synchronous proof timed out")
	}
}

func (handler proveHandler) isBatchOperation(circuitType common.CircuitType) bool {
	switch circuitType {
	case common.BatchAddressAppendCircuitType:
		return true
	default:
		return false
	}
}

func GetQueueNameForCircuit(circuitType common.CircuitType) string {
	switch circuitType {
	case common.BatchAddressAppendCircuitType:
		return "zk_address_append_queue"
	case common.AggregateCircuitType,
		common.NullifierFoldCircuitType,
		common.MergeChainCircuitType:
		// These recursive requests contain proofs and public commitments, not
		// wallet secrets. Raw transfer and merge witnesses are deliberately
		// synchronous so Redis never persists their private key material.
		return "zk_transfer_queue"
	default:
		return ""
	}
}

func (handler proveHandler) getEstimatedTime(circuitType common.CircuitType) string {
	switch circuitType {
	case common.BatchAddressAppendCircuitType:
		return "10-30 seconds"
	case common.AggregateCircuitType, common.NullifierFoldCircuitType, common.MergeChainCircuitType:
		return "60-600 seconds"
	case common.TransferP256RingCircuitType:
		return "30-180 seconds"
	default:
		return "1-3 seconds"
	}
}

func (handler proveHandler) getEstimatedTimeSeconds(circuitType common.CircuitType) int {
	switch circuitType {
	case common.BatchAddressAppendCircuitType:
		return 30
	case common.TransferP256RingCircuitType:
		return 180
	case common.TransferConfidentialCircuitType, common.TransferRingCircuitType, common.TransferRingAuthorityCircuitType:
		return 30
	case common.AggregateCircuitType, common.MergeChainCircuitType:
		return 600
	case common.NullifierFoldCircuitType:
		return 600
	case common.MergeCircuitType, common.MergeRingCircuitType:
		return 60
	case common.SquadsKeyEncryptionCircuitType:
		return 120
	case common.SquadsRingCircuitType:
		return 90
	case common.SquadsRingFoldCircuitType, common.SquadsKeyEncryptionFoldCircuitType:
		return 600
	default:
		return 1
	}
}

func (handler proveHandler) processProofSync(ctx context.Context, buf []byte) (*common.Proof, *Error) {
	proofRequestMeta, err := common.ParseProofRequestMeta(buf)
	if err != nil {
		return nil, malformedBodyError(err)
	}

	// The last point the work can stop. A Groth16 prove cannot be interrupted,
	// so a request whose client already left must not reach a proving key.
	if err := ctx.Err(); err != nil {
		return nil, requestAbandonedError(err)
	}

	switch proofRequestMeta.CircuitType {
	case common.BatchAddressAppendCircuitType:
		return handler.batchAddressAppendProof(buf)
	case common.TransferConfidentialCircuitType,
		common.TransferRingCircuitType,
		common.TransferRingAuthorityCircuitType:
		return handler.transferEddsaProof(buf)
	case common.TransferP256RingCircuitType:
		return handler.transferP256Proof(buf)
	case common.AggregateCircuitType:
		return handler.aggregateProof(buf)
	case common.NullifierFoldCircuitType:
		return handler.nullifierFoldProof(buf)
	case common.MergeChainCircuitType:
		return handler.mergeChainProof(buf)
	case common.MergeCircuitType, common.MergeRingCircuitType:
		return handler.mergeProof(buf, proofRequestMeta.CircuitType)
	case common.SquadsRingCircuitType:
		return handler.squadsRingProof(buf)
	case common.SquadsKeyEncryptionCircuitType:
		return handler.squadsKeyEncryptionProof(buf)
	case common.SquadsRingFoldCircuitType:
		return handler.squadsRingFoldProof(buf)
	case common.SquadsKeyEncryptionFoldCircuitType:
		return handler.squadsKeyEncryptionFoldProof(buf)
	default:
		return nil, malformedBodyError(fmt.Errorf("unknown circuit type: %s", proofRequestMeta.CircuitType))
	}
}

func (handler proveHandler) mergeProof(buf []byte, circuitType common.CircuitType) (*common.Proof, *Error) {
	var params mergeprover.MergeParameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}

	ps, err := handler.keyManager.GetTransferSystem(circuitType, mergeprover.MergeNInputs, mergeprover.MergeNOutputs)
	if err != nil {
		return nil, provingError(fmt.Errorf("%s: %w", circuitType, err))
	}

	proof, err := mergeprover.ProveMerge(ps, &params)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) batchAddressAppendProof(buf []byte) (*common.Proof, *Error) {
	var params nullifiertree.BatchAddressAppendParameters
	err := json.Unmarshal(buf, &params)
	if err != nil {
		return nil, malformedBodyError(err)
	}

	treeHeight := params.TreeHeight
	batchSize := params.BatchSize

	ps, err := handler.keyManager.GetBatchSystem(common.BatchAddressAppendCircuitType, treeHeight, batchSize)
	if err != nil {
		return nil, provingError(fmt.Errorf("batch address append: %w", err))
	}

	proof, err := nullifiertree.ProveBatchAddressAppend(ps, &params)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) squadsRingProof(buf []byte) (*common.Proof, *Error) {
	var params squadsring.RingParameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}

	ps, err := handler.keyManager.GetRingSystem(params.NInputs, params.NOutputs)
	if err != nil {
		return nil, provingError(fmt.Errorf("squads-ring: %w", err))
	}

	proof, err := squadsring.ProveRing(ps, &params)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) squadsKeyEncryptionProof(buf []byte) (*common.Proof, *Error) {
	var params keyencryption.KeyEncryptionParameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}

	ps, err := handler.keyManager.GetKeyEncryptionSystem(params.NumKeys)
	if err != nil {
		return nil, provingError(fmt.Errorf("squads-key-encryption: %w", err))
	}

	proof, err := keyencryption.ProveKeyEncryption(ps, &params)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) squadsRingFoldProof(buf []byte) (*common.Proof, *Error) {
	var params ringfold.Parameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}

	ps, err := handler.keyManager.GetRingFoldSystem(
		params.Params.NInputs,
		params.Params.NOutputs,
		params.Params.Legs,
	)
	if err != nil {
		return nil, provingError(fmt.Errorf("squads-ring-fold: %w", err))
	}

	proof, err := ringfold.ProveFold(ps, params.Legs)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) squadsKeyEncryptionFoldProof(buf []byte) (*common.Proof, *Error) {
	var params keyencryptionfold.Parameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}

	ps, err := handler.keyManager.GetKeyEncryptionFoldSystem(
		params.Params.KeysPerLeg,
		params.Params.Legs,
	)
	if err != nil {
		return nil, provingError(fmt.Errorf("squads-key-encryption-fold: %w", err))
	}

	proof, err := keyencryptionfold.ProveFold(ps, params.Legs)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) transferEddsaProof(buf []byte) (*common.Proof, *Error) {
	var params transfereddsaonly.TransferParameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}

	circuitType := params.Variant.CircuitType()
	ps, err := handler.keyManager.GetTransferSystem(circuitType, params.NInputs, params.NOutputs)
	if err != nil {
		return nil, provingError(fmt.Errorf("transfer-eddsa: %w", err))
	}

	proof, err := transfereddsaonly.ProveTransfer(ps, &params)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) transferP256Proof(buf []byte) (*common.Proof, *Error) {
	var params transfereddsaonly.P256TransferParameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}
	ps, err := handler.keyManager.GetTransferSystem(
		common.TransferP256RingCircuitType,
		params.NInputs,
		params.NOutputs,
	)
	if err != nil {
		return nil, provingError(fmt.Errorf("transfer-p256: %w", err))
	}
	proof, err := transfereddsaonly.ProveP256Transfer(ps, &params)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) aggregateProof(buf []byte) (*common.Proof, *Error) {
	var params aggregateprover.Parameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}
	ps, err := handler.keyManager.GetAggregateSystemSlots(params.Params.Slots)
	if err != nil {
		return nil, provingError(fmt.Errorf("aggregate: %w", err))
	}
	proof, backend, err := aggregateprover.ProveAggregateBackend(ps, params.Legs)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	logging.Logger().Info().Str("backend", string(backend)).Msg("aggregate proof served")
	return proof, nil
}

func (handler proveHandler) nullifierFoldProof(buf []byte) (*common.Proof, *Error) {
	var params nullifierfoldprover.Parameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}
	ps, err := handler.keyManager.GetNullifierFoldSystem(
		params.Params.TreeHeight,
		params.Params.BatchSize,
		params.Params.Run,
	)
	if err != nil {
		return nil, provingError(fmt.Errorf("nullifier-fold: %w", err))
	}
	proof, err := nullifierfoldprover.ProveFold(ps, params.Run)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) mergeChainProof(buf []byte) (*common.Proof, *Error) {
	var params mergechainprover.Parameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}
	ps, err := handler.keyManager.GetMergeChainSystem(params.Params.Levels32())
	if err != nil {
		return nil, provingError(fmt.Errorf("merge chain: %w", err))
	}
	proof, err := mergechainprover.ProveMergeChain(ps, params.Params, params.Legs)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	logging.Logger().Info().Msg("received health check request")
	responseBytes, err := json.Marshal(map[string]string{"status": "ok"})
	if err != nil {
		logging.Logger().Error().Err(err).Msg("error marshaling response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(responseBytes)
	if err != nil {
		logging.Logger().Error().Err(err).Msg("error writing response")
	}
}
