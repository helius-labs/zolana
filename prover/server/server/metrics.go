package server

import (
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"zolana/prover/logging"
)

var (
	ProofRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prover_proof_requests_total",
			Help: "Total number of proof generation requests by circuit type",
		},
		[]string{"circuit_type"},
	)

	ProofGenerationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "prover_proof_generation_duration_seconds",
			Help:    "Duration of proof generation in seconds",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 15),
		},
		[]string{"circuit_type"},
	)

	ProofGenerationErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prover_proof_generation_errors_total",
			Help: "Total number of proof generation errors by circuit type",
		},
		[]string{"circuit_type", "error_type"},
	)

	ProofPanicsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prover_proof_panics_total",
			Help: "Total number of panics recovered during proof processing",
		},
		[]string{"circuit_type"},
	)

	QueueWaitTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "prover_queue_wait_time_seconds",
			Help:    "Time spent waiting in queue before processing",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 12),
		},
		[]string{"circuit_type"},
	)

	JobsProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prover_jobs_processed_total",
			Help: "Total number of jobs processed",
		},
		[]string{"status"},
	)

	ExpiredJobsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prover_expired_jobs_total",
			Help: "Total number of expired jobs that were skipped",
		},
		[]string{"queue"},
	)

	ActiveJobs = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "prover_active_jobs",
			Help: "Number of currently active proof generation jobs",
		},
	)

	CircuitInputSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "prover_circuit_input_size_bytes",
			Help:    "Size of circuit inputs in bytes",
			Buckets: prometheus.ExponentialBuckets(1024, 2, 15),
		},
		[]string{"circuit_type"},
	)

	CircuitProofSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "prover_circuit_proof_size_bytes",
			Help:    "Size of generated proofs in bytes",
			Buckets: prometheus.ExponentialBuckets(256, 2, 10),
		},
		[]string{"circuit_type"},
	)

	// Memory metrics for proof generation
	ProofMemoryUsage = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "prover_proof_memory_usage_bytes",
			Help:    "Memory allocated during proof generation (heap alloc delta)",
			Buckets: prometheus.ExponentialBuckets(1024*1024*100, 2, 12), // 100MB to ~200GB
		},
		[]string{"circuit_type"},
	)

	ProofPeakMemory = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_proof_peak_memory_bytes",
			Help: "Peak memory observed during proof generation by circuit type",
		},
		[]string{"circuit_type"},
	)

	// Duration gauges beside the histogram. The CloudWatch agent drops
	// histogram series, so dashboards can only read gauges and counters.
	ProofDurationLast = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_proof_duration_seconds_last",
			Help: "Duration of the most recent proof, by circuit type",
		},
		[]string{"circuit_type"},
	)

	ProofDurationMean = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_proof_duration_seconds_mean",
			Help: "Mean duration over the last 100 proofs, by circuit type",
		},
		[]string{"circuit_type"},
	)

	ProofDurationMax = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_proof_duration_seconds_max",
			Help: "Slowest of the last 100 proofs, by circuit type",
		},
		[]string{"circuit_type"},
	)

	// Enqueue-to-dequeue wait, stamped from the job's CreatedAt at dequeue.
	QueueWaitLast = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_queue_wait_seconds_last",
			Help: "Enqueue-to-dequeue delay of the most recent job, by queue",
		},
		[]string{"queue"},
	)

	QueueWaitMean = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_queue_wait_seconds_mean",
			Help: "Mean enqueue-to-dequeue delay over the last 100 jobs, by queue",
		},
		[]string{"queue"},
	)

	QueueWaitMax = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_queue_wait_seconds_max",
			Help: "Longest enqueue-to-dequeue delay over the last 100 jobs, by queue",
		},
		[]string{"queue"},
	)

	// Per-stage time of the dequeue loop. One goroutine per queue feeds every
	// proof worker, so the loop's per-job cost caps the admission rate.
	//
	//   dequeue   - blocked in BLPop, high only when there is no work
	//   dedup     - the cached-result and cached-failure lookups
	//   semaphore - all workers busy, the one healthy reason to stall
	DispatchLast = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_dispatch_seconds_last",
			Help: "Most recent duration of a dequeue-loop stage, by queue and stage",
		},
		[]string{"queue", "stage"},
	)

	DispatchMean = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_dispatch_seconds_mean",
			Help: "Mean duration of a dequeue-loop stage over the last 100 jobs",
		},
		[]string{"queue", "stage"},
	)

	DispatchMax = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_dispatch_seconds_max",
			Help: "Longest duration of a dequeue-loop stage over the last 100 jobs",
		},
		[]string{"queue", "stage"},
	)

	// Finish-to-pickup delay of pushed replies, the last edge of the wait
	// breakdown. Queue wait and the dispatch stages end at proof completion,
	// this one ends when a blocked waiter receives the reply.
	ResultDeliveredLast = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_result_delivered_seconds_last",
			Help: "Finish-to-pickup delay of the most recent delivered reply, by queue",
		},
		[]string{"queue"},
	)

	ResultDeliveredMean = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_result_delivered_seconds_mean",
			Help: "Mean finish-to-pickup delay over the last 100 delivered replies, by queue",
		},
		[]string{"queue"},
	)

	ResultDeliveredMax = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_result_delivered_seconds_max",
			Help: "Longest finish-to-pickup delay over the last 100 delivered replies, by queue",
		},
		[]string{"queue"},
	)

	// Autoscaling tracks backlog, not CPU. CPU saturates at 100% and cannot
	// separate busy from backlogged. Every task reports the same global depth,
	// the queue is one Redis list. The scaling policy divides by task count.
	QueueDepth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_queue_depth",
			Help: "Jobs currently waiting in each queue",
		},
		[]string{"queue"},
	)

	SystemMemoryUsage = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_system_memory_bytes",
			Help: "System memory statistics",
		},
		[]string{"type"}, // heap_alloc, heap_sys, heap_inuse, sys
	)
)

type MetricTimer struct {
	start          time.Time
	circuitType    string
	startHeapAlloc uint64
}

// StartProofTimer marks the beginning of one proof execution. It must not
// count requests. proveHandler counts each request once at the routing point,
// a count here would double the queued path.
func StartProofTimer(circuitType string) *MetricTimer {
	ActiveJobs.Inc()

	// Capture memory state before proof generation
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Update system memory gauges
	SystemMemoryUsage.WithLabelValues("heap_alloc").Set(float64(memStats.HeapAlloc))
	SystemMemoryUsage.WithLabelValues("heap_sys").Set(float64(memStats.HeapSys))
	SystemMemoryUsage.WithLabelValues("heap_inuse").Set(float64(memStats.HeapInuse))
	SystemMemoryUsage.WithLabelValues("sys").Set(float64(memStats.Sys))

	return &MetricTimer{
		start:          time.Now(),
		circuitType:    circuitType,
		startHeapAlloc: memStats.HeapAlloc,
	}
}

// recentWindow is the number of proofs the rolling duration gauges average over.
// Small enough to react to a change in load, large enough that one slow proof
// does not dominate the mean.
const recentWindow = 100

// rollingStats keeps the last recentWindow observations per key. A Prometheus
// Gauge cannot be read back, so the mean, the max, and the peak live here.
type rollingStats struct {
	mu        sync.Mutex
	byCircuit map[string]*window
}

type window struct {
	samples []float64
	next    int
	peakMem float64
}

var rolling = &rollingStats{byCircuit: map[string]*window{}}

// Queue waits keep their own window, keyed by queue rather than circuit.
var queueWaits = &rollingStats{byCircuit: map[string]*window{}}

// RecordQueueWait publishes the enqueue-to-dequeue wait of one job.
func RecordQueueWait(queueName string, waited time.Duration) {
	seconds := waited.Seconds()
	if seconds < 0 {
		return
	}
	mean, max, _ := queueWaits.observe(queueName, seconds, 0)
	QueueWaitLast.WithLabelValues(queueName).Set(seconds)
	QueueWaitMean.WithLabelValues(queueName).Set(mean)
	QueueWaitMax.WithLabelValues(queueName).Set(max)
}

// Dispatch stages keep their own window, keyed by queue and stage together.
var dispatchStages = &rollingStats{byCircuit: map[string]*window{}}

// RecordDispatchStage publishes the duration of one dequeue-loop stage.
// Stage names are fixed so the series stay bounded.
func RecordDispatchStage(queueName, stage string, took time.Duration) {
	seconds := took.Seconds()
	if seconds < 0 {
		return
	}
	mean, max, _ := dispatchStages.observe(queueName+"|"+stage, seconds, 0)
	DispatchLast.WithLabelValues(queueName, stage).Set(seconds)
	DispatchMean.WithLabelValues(queueName, stage).Set(mean)
	DispatchMax.WithLabelValues(queueName, stage).Set(max)
}

// Delivered replies keep their own window, keyed by queue.
var resultDeliveries = &rollingStats{byCircuit: map[string]*window{}}

// RecordResultDelivered publishes the finish-to-pickup delay of one reply.
func RecordResultDelivered(queueName string, delay time.Duration) {
	seconds := delay.Seconds()
	if seconds < 0 {
		return
	}
	mean, max, _ := resultDeliveries.observe(queueName, seconds, 0)
	ResultDeliveredLast.WithLabelValues(queueName).Set(seconds)
	ResultDeliveredMean.WithLabelValues(queueName).Set(mean)
	ResultDeliveredMax.WithLabelValues(queueName).Set(max)
}

// observe records a duration and a memory delta, returning the mean and max
// duration over the retained window and the all-time peak memory.
func (r *rollingStats) observe(circuit string, duration, memBytes float64) (mean, max, peakMem float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	w, ok := r.byCircuit[circuit]
	if !ok {
		w = &window{samples: make([]float64, 0, recentWindow)}
		r.byCircuit[circuit] = w
	}

	if len(w.samples) < recentWindow {
		w.samples = append(w.samples, duration)
	} else {
		w.samples[w.next] = duration
		w.next = (w.next + 1) % recentWindow
	}

	if memBytes > w.peakMem {
		w.peakMem = memBytes
	}

	var total float64
	for _, sample := range w.samples {
		total += sample
		if sample > max {
			max = sample
		}
	}
	return total / float64(len(w.samples)), max, w.peakMem
}

func (t *MetricTimer) ObserveDuration() {
	duration := time.Since(t.start).Seconds()
	ProofGenerationDuration.WithLabelValues(t.circuitType).Observe(duration)
	ActiveJobs.Dec()

	// Capture memory state after proof generation
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Calculate memory delta (may be negative due to GC, use max with 0)
	memDelta := int64(memStats.HeapAlloc) - int64(t.startHeapAlloc)
	if memDelta < 0 {
		memDelta = 0
	}

	// Record memory usage for this proof
	ProofMemoryUsage.WithLabelValues(t.circuitType).Observe(float64(memDelta))

	// Peak memory, and the duration gauges that survive the metrics agent.
	mean, max, peakMem := rolling.observe(t.circuitType, duration, float64(memDelta))
	ProofPeakMemory.WithLabelValues(t.circuitType).Set(peakMem)
	ProofDurationLast.WithLabelValues(t.circuitType).Set(duration)
	ProofDurationMean.WithLabelValues(t.circuitType).Set(mean)
	ProofDurationMax.WithLabelValues(t.circuitType).Set(max)

	// Update system memory gauges
	SystemMemoryUsage.WithLabelValues("heap_alloc").Set(float64(memStats.HeapAlloc))
	SystemMemoryUsage.WithLabelValues("heap_sys").Set(float64(memStats.HeapSys))
	SystemMemoryUsage.WithLabelValues("heap_inuse").Set(float64(memStats.HeapInuse))
	SystemMemoryUsage.WithLabelValues("sys").Set(float64(memStats.Sys))

	// Log memory usage for debugging
	logging.Logger().Info().
		Str("circuit_type", t.circuitType).
		Float64("duration_sec", duration).
		Uint64("start_heap_mb", t.startHeapAlloc/1024/1024).
		Uint64("end_heap_mb", memStats.HeapAlloc/1024/1024).
		Int64("delta_mb", memDelta/1024/1024).
		Uint64("sys_mb", memStats.Sys/1024/1024).
		Msg("Proof generation completed with memory stats")
}

func (t *MetricTimer) ObserveError(errorType string) {
	ProofGenerationErrors.WithLabelValues(t.circuitType, errorType).Inc()
	ActiveJobs.Dec()

	// Still record memory stats on error
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	SystemMemoryUsage.WithLabelValues("heap_alloc").Set(float64(memStats.HeapAlloc))
	SystemMemoryUsage.WithLabelValues("heap_sys").Set(float64(memStats.HeapSys))
	SystemMemoryUsage.WithLabelValues("heap_inuse").Set(float64(memStats.HeapInuse))
	SystemMemoryUsage.WithLabelValues("sys").Set(float64(memStats.Sys))
}

func RecordJobComplete(success bool) {
	if success {
		JobsProcessed.WithLabelValues("completed").Inc()
	} else {
		JobsProcessed.WithLabelValues("failed").Inc()
	}
}

func RecordCircuitInputSize(circuitType string, sizeBytes int) {
	CircuitInputSize.WithLabelValues(circuitType).Observe(float64(sizeBytes))
}

func RecordProofSize(circuitType string, sizeBytes int) {
	CircuitProofSize.WithLabelValues(circuitType).Observe(float64(sizeBytes))
}
