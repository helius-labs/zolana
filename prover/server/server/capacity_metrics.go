package server

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"zolana/prover/logging"
	"zolana/prover/prover/timing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var ProofsCompleted = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "prover_proofs_completed_total", Help: "Completed proofs across synchronous and queued delivery",
}, []string{"circuit_type"})

var ProofHTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name: "prover_http_request_duration_seconds", Help: "Proof HTTP duration including preparation and admission",
	Buckets: prometheus.ExponentialBuckets(0.025, 2, 15),
}, []string{"route", "status"})

var SyncAdmissionWait = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name: "prover_sync_admission_wait_seconds", Help: "Time spent acquiring a synchronous proof permit",
	Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
}, []string{"outcome"})

func capacityMetrics(execution *TransferExecution, readiness *Readiness) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "prover_transfer_waiting", Help: "Synchronous transfer requests waiting for execution"}, func() float64 { return float64(execution.admission.waiting.Load()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "prover_transfer_capacity", Help: "Shared transfer execution permits"}, func() float64 { return float64(cap(execution.admission.permits)) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "prover_transfer_active", Help: "Occupied transfer execution permits"}, func() float64 { return float64(len(execution.admission.permits)) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "prover_ready", Help: "Configured proving keys have loaded"}, func() float64 {
			if readiness.Ready() {
				return 1
			}
			return 0
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "prover_gomaxprocs", Help: "Go scheduler CPU parallelism"}, func() float64 { return float64(runtime.GOMAXPROCS(0)) }),
	)
	return promhttp.HandlerFor(prometheus.Gatherers{prometheus.DefaultGatherer, registry}, promhttp.HandlerOpts{})
}

type proofResponse struct {
	http.ResponseWriter
	status int
	timing *timing.Trace
}

func (w *proofResponse) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	if w.timing != nil {
		spans := w.timing.Snapshot()
		encoded, _ := json.Marshal(spans)
		w.Header().Set("Server-Timing", timing.Header(spans))
		w.Header().Set("X-Prover-Timing", string(encoded))
		w.Header().Set("Cache-Control", "no-store")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *proofResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func observeProofHTTP(route string, handler http.Handler) http.Handler {
	timingsEnabled := os.Getenv("PROVER_REQUEST_TIMING") == "true"
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		start := time.Now()
		response := &proofResponse{ResponseWriter: w}
		if timingsEnabled && request.Header.Get("X-Prover-Timing") == "true" {
			response.timing = timing.New()
			request = request.WithContext(response.timing.Context(request.Context()))
			requestID, err := uuid.Parse(request.Header.Get("X-Request-ID"))
			if err != nil {
				requestID = uuid.New()
			}
			w.Header().Set("X-Request-ID", requestID.String())
		}
		defer func() {
			status := response.status
			if status == 0 {
				status = http.StatusOK
			}
			ProofHTTPDuration.WithLabelValues(route, strconv.Itoa(status/100)+"xx").Observe(time.Since(start).Seconds())
			if response.timing != nil {
				logging.Logger().Info().
					Str("request_id", w.Header().Get("X-Request-ID")).
					Str("route", route).
					Int("status", status).
					Interface("spans", response.timing.Snapshot()).
					Msg("Proof request timing")
			}
		}()
		handler.ServeHTTP(response, request)
	})
}
