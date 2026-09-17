package server

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

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
}

func (w *proofResponse) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *proofResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func observeProofHTTP(route string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		start := time.Now()
		response := &proofResponse{ResponseWriter: w}
		defer func() {
			status := response.status
			if status == 0 {
				status = http.StatusOK
			}
			ProofHTTPDuration.WithLabelValues(route, strconv.Itoa(status/100)+"xx").Observe(time.Since(start).Seconds())
		}()
		handler.ServeHTTP(response, request)
	})
}
