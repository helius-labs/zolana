package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"zolana/prover/logging"
	"zolana/prover/prover/common"
	customring "zolana/prover/prover/custom_ring"
	mergeprover "zolana/prover/prover/merge"
	nullifiertree "zolana/prover/prover/nullifier_tree"
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

	jobID := r.URL.Query().Get("jobId")
	if jobID == "" {
		malformedBodyError(fmt.Errorf("jobId parameter required")).send(w)
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
			"jobId":  jobID,
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

	jobExists, jobStatus, jobInfo, lookupErr := handler.checkJobExistsDetailed(jobID)
	if lookupErr != nil {
		logging.Logger().Error().
			Err(lookupErr).
			Str("job_id", jobID).
			Msg("Job status lookup failed")

		unavailableError := &Error{
			StatusCode: http.StatusServiceUnavailable,
			Code:       "status_unavailable",
			Message:    fmt.Sprintf("Status for job %s is temporarily unavailable. Retry shortly.", jobID),
		}
		unavailableError.send(w)
		return
	}

	if !jobExists {
		// Fallback: check job metadata - this catches jobs that were submitted but not yet
		// visible in queues due to Redis replica lag or race conditions
		jobMeta, metaErr := handler.redisQueue.GetJobMeta(jobID)
		if metaErr != nil {
			logging.Logger().Warn().
				Err(metaErr).
				Str("job_id", jobID).
				Msg("Error checking job metadata")
		}

		if jobMeta != nil {
			// Job was submitted (we have metadata) but not found in queues - return queued status
			logging.Logger().Info().
				Str("job_id", jobID).
				Interface("job_meta", jobMeta).
				Msg("Job not found in queues but metadata exists - returning queued status")

			response := map[string]interface{}{
				"jobId":   jobID,
				"status":  "queued",
				"message": "Job is queued and waiting to be processed",
			}
			if circuitType, ok := jobMeta["circuitType"]; ok {
				response["circuitType"] = circuitType
			}
			if submittedAt, ok := jobMeta["submittedAt"]; ok {
				response["submittedAt"] = submittedAt
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

		// Clean up any stale in-flight marker for this job ID
		// This allows new requests with the same input to create fresh jobs
		handler.redisQueue.CleanupStaleInFlightMarker(jobID)

		notFoundError := &Error{
			StatusCode: http.StatusNotFound,
			Code:       "job_not_found",
			Message:    fmt.Sprintf("Job with ID %s not found. It may have expired or never existed.", jobID),
		}
		notFoundError.send(w)
		return
	}

	// Log job status without payload to avoid filling up log buffer
	logEvent := logging.Logger().Info().
		Str("job_id", jobID).
		Str("status", jobStatus)
	if jobInfo != nil {
		if ct, ok := jobInfo["circuitType"]; ok {
			logEvent = logEvent.Interface("circuit_type", ct)
		}
		if ca, ok := jobInfo["createdAt"]; ok {
			logEvent = logEvent.Interface("created_at", ca)
		}
	}
	logEvent.Msg("Job found but not completed")

	response := map[string]interface{}{
		"jobId":  jobID,
		"status": jobStatus,
	}

	// Handle completed jobs - include result if available
	if jobStatus == "completed" && jobInfo != nil {
		if result, ok := jobInfo["result"]; ok {
			response["result"] = result
			logging.Logger().Info().
				Str("job_id", jobID).
				Msg("Returning result from checkJobExistsDetailed")
		}
	}

	// Handle failed jobs specially - extract actual error details
	if jobStatus == "failed" && jobInfo != nil {
		// The details arrive already decoded, alongside the status they belong
		// to. They used to be a JSON string lifted out of the failed queue's
		// entry, which meant finding that entry by scanning the queue.
		if failureDetails, ok := jobInfo["failure"].(map[string]interface{}); ok {
			if errorMsg, ok := failureDetails["error"].(string); ok {
				response["message"] = fmt.Sprintf("Job processing failed: %s", errorMsg)
				response["error"] = errorMsg
			}
			if failedAt, ok := failureDetails["failedAt"]; ok {
				response["failedAt"] = failedAt
			}
			if originalJob, ok := failureDetails["originalJob"].(map[string]interface{}); ok {
				if circuitType, ok := originalJob["circuitType"]; ok {
					response["circuitType"] = circuitType
				}
			}
		} else {
			response["message"] = "Job processing failed. No failure details available."
		}
	} else {
		// Use generic message for non-failed jobs
		response["message"] = getStatusMessage(jobStatus)

		if jobInfo != nil {
			if createdAt, ok := jobInfo["createdAt"]; ok {
				response["createdAt"] = createdAt
			}
			if circuitType, ok := jobInfo["circuitType"]; ok {
				response["circuitType"] = circuitType
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")

	// Return 200 OK if job is completed with result, otherwise 202 Accepted
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

type QueueConfig struct {
	RedisURL string
	Enabled  bool
}

type EnhancedConfig struct {
	ProverAddress  string
	MetricsAddress string
	Queue          *QueueConfig
}

type proveHandler struct {
	keyManager  *common.LazyKeyManager
	redisQueue  *RedisQueue
	enableQueue bool
	// Bounds proving done inside a request. Shared across requests, so it must
	// be the same instance for every one of them.
	admission *syncAdmission
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

// checkJobExistsDetailed answers a status poll with two O(1) Redis reads.
//
// This is the hottest path in the server -- a client polls it from submission
// until its proof lands, so polls outnumber jobs by orders of magnitude. It
// used to walk entire Redis lists with LRANGE key 0 -1: the job's own queue,
// then the processing queue, then zk_failed_queue, then zk_results_queue,
// unmarshalling every element. A 220-worker run drove ~57 such polls a second
// against a results queue holding 8237 entries, which is on the order of half a
// million element reads per second from a single-threaded Redis. Redis returned
// i/o timeouts, dispatch stalled behind them, health checks failed, ECS
// replaced the tasks, and the in-flight jobs on them were orphaned.
//
// The scans existed only because the metadata was written once at submission
// and never updated, so "queued" and "processing" could not be told apart
// without looking. The workers now keep that field current (MarkJobProcessing,
// MarkJobFailed), which costs one SET per job, so the status is simply read.
//
// A Redis failure is reported as an error rather than as "not found": the two
// are indistinguishable to a caller that only gets a bool, and answering
// "unknown" during a blip 404s a live job and lets the caller clear its
// in-flight marker.
func (handler proofStatusHandler) checkJobExistsDetailed(
	jobID string,
) (bool, string, map[string]interface{}, error) {
	// Completion is answered by the result index. This is the common terminal
	// case and stays first.
	result, err := handler.redisQueue.GetResult(jobID)
	if err == nil && result != nil {
		logging.Logger().Debug().
			Str("job_id", jobID).
			Msg("Job found in result cache")

		return true, "completed", map[string]interface{}{
			"result":       result,
			"resultCached": true,
		}, nil
	}

	jobMeta, metaErr := handler.redisQueue.GetJobMeta(jobID)
	if metaErr != nil {
		return false, "", nil, fmt.Errorf("failed to read job meta: %w", metaErr)
	}
	if jobMeta == nil {
		// Metadata is deleted on success and expires an hour after submission,
		// so an unknown id is genuinely unknown: either it never existed, or it
		// completed long enough ago that its result is gone too.
		return false, "", nil, nil
	}

	status := "queued"
	if metaStatus, ok := jobMeta["status"].(string); ok {
		status = metaStatus
	}

	jobInfo := map[string]interface{}{
		"circuitType": jobMeta["circuitType"],
		"submittedAt": jobMeta["submittedAt"],
		"fromMeta":    true,
	}
	// A failure carries its reason with it, so the caller gets the same detail
	// the failed queue used to supply.
	if failure, ok := jobMeta["failure"].(map[string]interface{}); ok {
		jobInfo["failure"] = failure
	}

	return true, status, jobInfo, nil
}

func (handler proveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	buf, err := io.ReadAll(r.Body)
	if err != nil {
		logging.Logger().Error().Err(err).Msg("Error reading request body")
		malformedBodyError(err).send(w)
		return
	}

	proofRequestMeta, err := common.ParseProofRequestMeta(buf)
	if err != nil {
		malformedBodyError(err).send(w)
		return
	}

	forceAsync := r.Header.Get("X-Async") == "true" || r.URL.Query().Get("async") == "true"
	forceSync := r.Header.Get("X-Sync") == "true" || r.URL.Query().Get("sync") == "true"

	queueAvailable := handler.enableQueue && handler.redisQueue != nil
	if proofRequestMeta.CircuitType == common.CustomRingAuditCircuitType && !queueAvailable {
		(&Error{
			StatusCode: http.StatusServiceUnavailable,
			Code:       "queue_unavailable",
			Message:    "custom ring audit proofs require the audit queue",
		}).send(w)
		return
	}
	circuitQueued := handler.shouldUseQueueForCircuit(proofRequestMeta.CircuitType)
	// `use_queue` is the decision, not the circuit's queueability: logging the
	// latter under that name said use_queue=true on requests that were proved in
	// the response, which is exactly the question the line exists to answer.
	if proofRequestMeta.CircuitType == common.CustomRingAuditCircuitType {
		forceSync = false
	}
	queued := useQueue(forceSync, forceAsync, circuitQueued, queueAvailable)

	logging.Logger().Info().
		Str("circuit_type", string(proofRequestMeta.CircuitType)).
		Bool("force_async", forceAsync).
		Bool("force_sync", forceSync).
		Bool("circuit_queued", circuitQueued).
		Bool("use_queue", queued).
		Bool("queue_available", queueAvailable).
		Msg("Processing prove request")

	// Counted here, once, because this is the only point every request passes
	// through exactly once. Counting inside the handlers double-counted the
	// queued path -- once at submission and again when the worker called
	// StartProofTimer -- while the direct-sync path counted once, so the metric
	// read 2x on the only path production uses. It reported 498 proofs for a run
	// whose logs show 249.
	ProofRequestsTotal.WithLabelValues(string(proofRequestMeta.CircuitType)).Inc()
	RecordCircuitInputSize(string(proofRequestMeta.CircuitType), len(buf))

	if queued {
		handler.handleAsyncProof(w, r, buf, proofRequestMeta)
	} else {
		handler.handleSyncProof(w, r, buf, proofRequestMeta)
	}
}

// useQueue decides which rail proves a request.
//
// X-Sync and X-Async were computed and logged here but never consulted, so a
// caller asking for its proof in the response still got a job handle to poll --
// the header looked supported and did nothing.
//
// A contradiction resolves to the queue: queueing cannot exceed a connection or
// load balancer idle timeout, and answering inside the request can. X-Async can
// only be honoured for a circuit that has a queue to go on; for anything else the
// sync path takes it, with the heavy-operation warning it already emits.
func useQueue(forceSync, forceAsync, circuitQueued, queueAvailable bool) bool {
	if !queueAvailable {
		return false
	}
	if forceAsync {
		return circuitQueued
	}
	if forceSync {
		return false
	}
	return circuitQueued
}

func (handler proveHandler) shouldUseQueueForCircuit(circuitType common.CircuitType) bool {
	if !handler.enableQueue || handler.redisQueue == nil {
		return false
	}

	// A circuit is queueable iff it has a dedicated queue. address-append is heavy
	// and must go async; transfer/merge circuits now share zk_transfer_queue so a
	// shared prover doesn't get stampeded by concurrent synchronous transfers.
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
		"queues":       stats,
		"totalPending": stats["zk_address_append_queue"] + stats["zk_transfer_queue"] + stats["zk_custom_ring_audit_queue"],
		"totalActive":  stats["zk_address_append_processing_queue"] + stats["zk_transfer_processing_queue"] + stats["zk_custom_ring_audit_processing_queue"],
		"totalFailed":  stats["zk_failed_queue"],
		"timestamp":    time.Now().Unix(),
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
		results["oldRequestsCleanup"] = map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	} else {
		results["oldRequestsCleanup"] = map[string]interface{}{
			"success": true,
		}
	}

	if err := handler.redisQueue.CleanupStuckProcessingJobs(); err != nil {
		results["stuckJobsCleanup"] = map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	} else {
		results["stuckJobsCleanup"] = map[string]interface{}{
			"success": true,
		}
	}

	if err := handler.redisQueue.CleanupOldFailedJobs(); err != nil {
		results["oldFailedCleanup"] = map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	} else {
		results["oldFailedCleanup"] = map[string]interface{}{
			"success": true,
		}
	}

	if err := handler.redisQueue.CleanupOldResultKeys(); err != nil {
		results["oldResultKeysCleanup"] = map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	} else {
		results["oldResultKeysCleanup"] = map[string]interface{}{
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
		ProverAddress:  config.ProverAddress,
		MetricsAddress: config.MetricsAddress,
		Queue: &QueueConfig{
			Enabled: redisQueue != nil,
		},
	}, redisQueue, keyManager)
}

func RunEnhanced(config *EnhancedConfig, redisQueue *RedisQueue, keyManager *common.LazyKeyManager) RunningJob {
	apiKey := getAPIKeyFromEnv()
	if apiKey != "" {
		logging.Logger().Info().Msg("API key authentication enabled for prover server")
	} else {
		logging.Logger().Warn().Msg("No API key configured - server will accept all requests. Set PROVER_API_KEY environment variable to enable authentication.")
	}
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsServer := &http.Server{Addr: config.MetricsAddress, Handler: metricsMux}
	metricsJob := spawnServerJob(metricsServer, "metrics server")
	logging.Logger().Info().Str("addr", config.MetricsAddress).Msg("metrics server started")

	proverMux := http.NewServeMux()

	proverMux.Handle("/prove", proveHandler{
		keyManager:  keyManager,
		redisQueue:  redisQueue,
		enableQueue: config.Queue != nil && config.Queue.Enabled,
		admission:   newSyncAdmission(syncPermits()),
	})

	proverMux.Handle("/health", healthHandler{
		circuits: servedCircuits(config.Queue != nil && config.Queue.Enabled),
	})

	if redisQueue != nil {
		proverMux.Handle("/prove/status", proofStatusHandler{redisQueue: redisQueue})
		proverMux.Handle("/queue/stats", queueStatsHandler{redisQueue: redisQueue})
		proverMux.Handle("/queue/health", queueHealthHandler{redisQueue: redisQueue})
		proverMux.Handle("/queue/cleanup", queueCleanupHandler{redisQueue: redisQueue})

		proverMux.HandleFunc("/queue/add", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			buf, err := io.ReadAll(r.Body)
			if err != nil {
				malformedBodyError(err).send(w)
				return
			}

			proofRequestMeta, err := common.ParseProofRequestMeta(buf)
			if err != nil {
				malformedBodyError(err).send(w)
				return
			}

			queueName := GetQueueNameForCircuit(proofRequestMeta.CircuitType)

			// Compute input hash for deduplication
			inputHash := ComputeInputHash(json.RawMessage(buf))

			// Check for existing in-flight job with same input
			dedupResult, err := redisQueue.DeduplicateJob(inputHash)
			if err != nil {
				logging.Logger().Error().
					Err(err).
					Str("input_hash", inputHash).
					Msg("Failed to deduplicate job")
				http.Error(w, "Failed to register job", http.StatusInternalServerError)
				return
			}

			// If deduplicated to an existing job, return early
			if dedupResult.IsDeduplicated {
				response := map[string]interface{}{
					"jobId":        dedupResult.JobID,
					"status":       "already_queued",
					"queue":        queueName,
					"circuitType":  string(proofRequestMeta.CircuitType),
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

			// This is a new job
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

			// Store input hash mapping for cleanup when job completes
			redisQueue.StoreInputHash(jobID, inputHash)

			err = redisQueue.EnqueueProof(queueName, job)
			if err != nil {
				// Clean up in-flight marker and metadata since we failed to enqueue
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
				"jobId":       jobID,
				"status":      "queued",
				"queue":       queueName,
				"circuitType": string(proofRequestMeta.CircuitType),
				"message":     fmt.Sprintf("Job queued in %s", queueName),
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			err = json.NewEncoder(w).Encode(response)
			if err != nil {
				return
			}
		})
	}

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

	authHandler := conditionalAuthMiddleware(apiKey)
	proverServer := &http.Server{Addr: config.ProverAddress, Handler: corsHandler(authHandler(proverMux))}
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

func provingError(err error) *Error {
	return &Error{StatusCode: http.StatusBadRequest, Code: "proving_error", Message: err.Error()}
}

func unexpectedError(err error) *Error {
	return &Error{StatusCode: http.StatusInternalServerError, Code: "unexpected_error", Message: err.Error()}
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
	ProverAddress  string
	MetricsAddress string
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
	circuits []common.CircuitType
}

// The audit circuit is absent without the queue, it is never proven synchronously.
func servedCircuits(queueEnabled bool) []common.CircuitType {
	circuits := []common.CircuitType{
		common.BatchAddressAppendCircuitType,
		common.TransferConfidentialCircuitType,
		common.TransferRingCircuitType,
		common.TransferP256RingCircuitType,
		common.TransferRingAuthorityCircuitType,
		common.MergeCircuitType,
		common.MergeRingCircuitType,
	}
	if queueEnabled {
		circuits = append(circuits, common.CustomRingAuditCircuitType)
	}
	return circuits
}

func (handler proveHandler) handleAsyncProof(w http.ResponseWriter, r *http.Request, buf []byte, meta common.ProofRequestMeta) {
	queueName := GetQueueNameForCircuit(meta.CircuitType)

	// Compute input hash for deduplication
	inputHash := ComputeInputHash(json.RawMessage(buf))

	// Check for existing in-flight job with same input
	dedupResult, err := handler.redisQueue.DeduplicateJob(inputHash)
	if err != nil {
		logging.Logger().Error().
			Err(err).
			Str("input_hash", inputHash).
			Msg("Failed to deduplicate job")
		http.Error(w, "Failed to register job", http.StatusInternalServerError)
		return
	}

	// If deduplicated to an existing job, return early
	if dedupResult.IsDeduplicated {
		response := map[string]interface{}{
			"jobId":        dedupResult.JobID,
			"status":       "already_queued",
			"circuitType":  string(meta.CircuitType),
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

	// This is a new job
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

	// Store input hash mapping for cleanup when job completes
	handler.redisQueue.StoreInputHash(jobID, inputHash)

	err = handler.redisQueue.EnqueueProof(queueName, job)
	if err != nil {
		logging.Logger().Error().Err(err).Msg("Failed to enqueue proof job")

		// Clean up in-flight marker and metadata since we failed to enqueue
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
		"jobId":         jobID,
		"status":        "queued",
		"circuitType":   string(meta.CircuitType),
		"queue":         queueName,
		"estimatedTime": estimatedTime,
		"statusUrl":     fmt.Sprintf("/prove/status?jobId=%s", jobID),
		"message":       fmt.Sprintf("Proof generation queued for %s circuit. Use statusUrl to check progress.", meta.CircuitType),
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
	if timeoutDuration < 10*time.Second {
		timeoutDuration = 10 * time.Second
	}
	if timeoutDuration > 300*time.Second {
		timeoutDuration = 300 * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeoutDuration)
	defer cancel()

	// Wait for a permit before starting work. Doing this here rather than around
	// the whole handler keeps parsing and validation off the bound: a malformed
	// request should be rejected while the prover is busy, not queued behind it.
	release, admitErr := handler.admission.admit(ctx)
	if admitErr != nil {
		logging.Logger().Warn().
			Str("circuit_type", string(meta.CircuitType)).
			Msg("Shedding synchronous proof at the concurrency limit")
		sendOverloaded(w, admitErr)
		return
	}

	type proofResult struct {
		proof *common.Proof
		err   *Error
	}

	resultChan := make(chan proofResult, 1)

	go func() {
		defer release()
		// Recover from panics to prevent server crash from malformed input
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

		proof, proofError := handler.processProofSync(buf)

		if proofError != nil {
			timer.ObserveError(proofError.Code)
			RecordJobComplete(false)
		} else {
			timer.ObserveDuration()
			RecordJobComplete(true)
			if proof != nil {
				proofBytes, _ := json.Marshal(proof)
				RecordProofSize(string(meta.CircuitType), len(proofBytes))
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
	case common.BatchAddressAppendCircuitType, common.CustomRingAuditCircuitType:
		return true
	default:
		return false
	}
}

func GetQueueNameForCircuit(circuitType common.CircuitType) string {
	switch circuitType {
	case common.BatchAddressAppendCircuitType:
		return "zk_address_append_queue"
	case common.TransferConfidentialCircuitType,
		common.TransferRingCircuitType,
		common.TransferP256RingCircuitType,
		common.TransferRingAuthorityCircuitType,
		common.MergeCircuitType,
		common.MergeRingCircuitType:
		return "zk_transfer_queue"
	case common.CustomRingAuditCircuitType:
		return "zk_custom_ring_audit_queue"
	default:
		return ""
	}
}

func (handler proveHandler) getEstimatedTime(circuitType common.CircuitType) string {
	switch circuitType {
	case common.BatchAddressAppendCircuitType:
		return "10-30 seconds"
	case common.TransferP256RingCircuitType, common.CustomRingAuditCircuitType:
		return "30-180 seconds"
	default:
		return "1-3 seconds"
	}
}

func (handler proveHandler) getEstimatedTimeSeconds(circuitType common.CircuitType) int {
	switch circuitType {
	case common.BatchAddressAppendCircuitType:
		return 30
	case common.TransferP256RingCircuitType, common.CustomRingAuditCircuitType:
		return 180
	case common.TransferConfidentialCircuitType, common.TransferRingCircuitType, common.TransferRingAuthorityCircuitType:
		return 30
	case common.MergeCircuitType, common.MergeRingCircuitType:
		// 8-in/1-out with emulated P256 + AES-CTR: heaviest shape.
		return 60
	default:
		return 1
	}
}

func (handler proveHandler) processProofSync(buf []byte) (*common.Proof, *Error) {
	proofRequestMeta, err := common.ParseProofRequestMeta(buf)
	if err != nil {
		return nil, malformedBodyError(err)
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
	case common.MergeCircuitType:
		return handler.mergeProof(buf)
	case common.MergeRingCircuitType:
		return handler.mergeRingProof(buf)
	case common.CustomRingAuditCircuitType:
		return handler.auditorKeyEncryptionProof(buf)
	default:
		return nil, malformedBodyError(fmt.Errorf("unknown circuit type: %s", proofRequestMeta.CircuitType))
	}
}

func (handler proveHandler) mergeProof(buf []byte) (*common.Proof, *Error) {
	var params mergeprover.MergeParameters
	if err := json.Unmarshal(buf, &params); err != nil {
		logging.Logger().Info().Msg("error Unmarshal")
		logging.Logger().Info().Msg(err.Error())
		return nil, malformedBodyError(err)
	}

	ps, err := handler.keyManager.GetTransferSystem(common.MergeCircuitType, mergeprover.MergeNInputs, mergeprover.MergeNOutputs)
	if err != nil {
		return nil, provingError(fmt.Errorf("merge: %w", err))
	}

	proof, err := mergeprover.ProveMerge(ps, &params)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) mergeRingProof(buf []byte) (*common.Proof, *Error) {
	var params mergeprover.MergeParameters
	if err := json.Unmarshal(buf, &params); err != nil {
		logging.Logger().Info().Msg("error Unmarshal")
		logging.Logger().Info().Msg(err.Error())
		return nil, malformedBodyError(err)
	}

	ps, err := handler.keyManager.GetTransferSystem(common.MergeRingCircuitType, mergeprover.MergeNInputs, mergeprover.MergeNOutputs)
	if err != nil {
		return nil, provingError(fmt.Errorf("merge-ring: %w", err))
	}

	proof, err := mergeprover.ProveMerge(ps, &params)
	if err != nil {
		logging.Logger().Err(err)
		return nil, provingError(err)
	}
	return proof, nil
}

func (handler proveHandler) auditorKeyEncryptionProof(buf []byte) (*common.Proof, *Error) {
	var params customring.AuditorKeyEncryptionParameters
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, malformedBodyError(err)
	}

	ps, err := handler.keyManager.GetGroth16System(common.CustomRingAuditCircuitType, customring.TransferVariant)
	if err != nil {
		return nil, provingError(fmt.Errorf("auditor-key-encryption: %w", err))
	}

	proof, err := customring.ProveAuditorKeyEncryption(ps, &params)
	if err != nil {
		return nil, provingError(errors.New("custom ring audit proof failed"))
	}
	return proof, nil
}

func (handler proveHandler) batchAddressAppendProof(buf []byte) (*common.Proof, *Error) {
	var params nullifiertree.BatchAddressAppendParameters
	err := json.Unmarshal(buf, &params)
	if err != nil {
		logging.Logger().Info().Msg("error Unmarshal")
		logging.Logger().Info().Msg(err.Error())
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

func (handler proveHandler) transferEddsaProof(buf []byte) (*common.Proof, *Error) {
	var params transfereddsaonly.TransferParameters
	if err := json.Unmarshal(buf, &params); err != nil {
		logging.Logger().Info().Msg("error Unmarshal")
		logging.Logger().Info().Msg(err.Error())
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

func (handler healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	logging.Logger().Info().Msg("received health check request")
	responseBytes, err := json.Marshal(map[string]interface{}{"status": "ok", "circuits": handler.circuits})
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
