package server

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

	// Sheds are the signal that the sync bound is too low for the offered load,
	// or that the fleet is undersized -- a client-visible 429, so it must be
	// visible here too rather than only in a log line.
	SyncProofsShedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "prover_sync_proofs_shed_total",
			Help: "Total number of synchronous proof requests rejected at the concurrency limit",
		},
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

	// Duration as GAUGES, alongside the histogram above.
	//
	// The histogram is the right Prometheus primitive and stays, but our
	// CloudWatch agent drops histogram metrics entirely -- not as _bucket, _sum or
	// _count -- so nothing derived from ProofGenerationDuration reaches our
	// dashboards. Measured, not assumed: after a run that generated 125 proofs,
	// the zolnet/prover namespace contained every gauge and counter and not one
	// histogram series.
	//
	// These carry the same information in a shape that survives the trip.
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

	// How long a job sat in Redis between being accepted and being picked up.
	//
	// The gap nobody measured. A client-observed "prove" phase of 118s was
	// reconciled against 0.28s of compute and an idle worker, and there was no
	// way to tell whether the missing two minutes were queue wait or the client
	// polling too slowly for its result. Stamped from the job's CreatedAt at
	// dequeue, which the expiry check already relies on.
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

	// Where the dequeue loop's time goes, broken down by stage.
	//
	// One goroutine per queue feeds every proof worker, so whatever that loop
	// spends per job is a hard ceiling on admission rate no matter how much
	// proving capacity exists behind it. Queue wait told us jobs waited ~105s;
	// it could not say why. The stages separate the three candidates:
	//
	//   dequeue   - blocked in BLPop. High only when there is no work.
	//   dedup     - the cached-result and cached-failure lookups. This is where
	//               an O(n) queue scan was costing 100ms + 1.53ms per stored
	//               result, capping admission at 0.8 jobs/s.
	//   semaphore - blocked because all workers are busy. This one is healthy
	//               backpressure; the other two are not.
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

	// How many jobs are waiting, published so autoscaling can react to backlog
	// rather than to CPU.
	//
	// CPU does track load here -- 30-43% at 2 tps, 98% at 4 tps -- but it is
	// bounded at 100%, and target tracking sizes the fleet by metric/target. At
	// 98% against a 70% target that is a 1.4x step whether five jobs are waiting
	// or five hundred, so recovering from a burst takes many cooldowns. Backlog
	// per task is unbounded and moves proportionally to the actual deficit. CPU
	// also cannot separate "busy" from "backlogged": 98% with an empty queue and
	// 98% with eighty jobs waiting are the same reading, and only one of them
	// has clients waiting.
	//
	// Every task reports the same global depth, since the queue is one Redis
	// list. Dividing by running task count is done in the scaling policy.
	QueueDepth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prover_queue_depth",
			Help: "Jobs currently waiting in each queue",
		},
		[]string{"queue"},
	)
)

type MetricTimer struct {
	start       time.Time
	circuitType string
}

// StartProofTimer marks the beginning of one proof *execution*.
//
// It deliberately does not touch ProofRequestsTotal. It used to, and since the
// HTTP handler counts the request too, every queued proof was counted twice --
// the metric read 498 for a run whose logs show 249 dequeues, 249 starts and
// 249 completions. Requests are counted once at the routing point in
// proveHandler; executions are visible through ActiveJobs, the duration gauges,
// and prover_jobs_processed_total.
func StartProofTimer(circuitType string) *MetricTimer {
	ActiveJobs.Inc()

	return &MetricTimer{start: time.Now(), circuitType: circuitType}
}

// recentWindow is the number of proofs the rolling duration gauges average over.
// Small enough to react to a change in load, large enough that one slow proof
// does not dominate the mean.
const recentWindow = 100

type rollingStats struct {
	mu        sync.Mutex
	byCircuit map[string]*window
}

type window struct {
	samples []float64
	next    int
}

var rolling = &rollingStats{byCircuit: map[string]*window{}}

// Queue waits keep their own window, keyed by queue rather than circuit.
var queueWaits = &rollingStats{byCircuit: map[string]*window{}}

// RecordQueueWait publishes how long a job sat between accept and dequeue.
//
// Called with the job's age at pickup. Zero CreatedAt means the job predates
// the field, so it is skipped rather than reported as an enormous wait.
func RecordQueueWait(queueName string, waited time.Duration) {
	seconds := waited.Seconds()
	if seconds < 0 {
		return
	}
	mean, max := queueWaits.observe(queueName, seconds)
	QueueWaitLast.WithLabelValues(queueName).Set(seconds)
	QueueWaitMean.WithLabelValues(queueName).Set(mean)
	QueueWaitMax.WithLabelValues(queueName).Set(max)
}

// Dispatch stages keep their own window, keyed by queue and stage together.
var dispatchStages = &rollingStats{byCircuit: map[string]*window{}}

// RecordDispatchStage publishes how long one stage of the dequeue loop took.
//
// Stage names are fixed ("dequeue", "dedup", "semaphore") so the series stay
// bounded; see the DispatchLast comment for what each one means.
func RecordDispatchStage(queueName, stage string, took time.Duration) {
	seconds := took.Seconds()
	if seconds < 0 {
		return
	}
	mean, max := dispatchStages.observe(queueName+"|"+stage, seconds)
	DispatchLast.WithLabelValues(queueName, stage).Set(seconds)
	DispatchMean.WithLabelValues(queueName, stage).Set(mean)
	DispatchMax.WithLabelValues(queueName, stage).Set(max)
}

func (r *rollingStats) observe(circuit string, duration float64) (mean, max float64) {
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

	var total float64
	for _, sample := range w.samples {
		total += sample
		if sample > max {
			max = sample
		}
	}
	return total / float64(len(w.samples)), max
}

func (t *MetricTimer) ObserveDuration() {
	ProofsCompleted.WithLabelValues(t.circuitType).Inc()
	duration := time.Since(t.start).Seconds()
	ProofGenerationDuration.WithLabelValues(t.circuitType).Observe(duration)
	ActiveJobs.Dec()

	mean, max := rolling.observe(t.circuitType, duration)
	ProofDurationLast.WithLabelValues(t.circuitType).Set(duration)
	ProofDurationMean.WithLabelValues(t.circuitType).Set(mean)
	ProofDurationMax.WithLabelValues(t.circuitType).Set(max)
}

func (t *MetricTimer) ObserveError(errorType string) {
	ProofGenerationErrors.WithLabelValues(t.circuitType, errorType).Inc()
	ActiveJobs.Dec()
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
