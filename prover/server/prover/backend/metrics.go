//go:build aeglos || aeglos_cpu

package backend

import (
	"time"

	aeglos "github.com/helius-labs/aeglos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	engineDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "prover_backend_stage_seconds", Help: "Proof backend stage duration", Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20)}, []string{"backend", "stage"})
	engineCache    = promauto.NewCounterVec(prometheus.CounterOpts{Name: "prover_backend_cache_requests_total", Help: "Proof backend cache lookups"}, []string{"result"})
	engineKeys     = promauto.NewGauge(prometheus.GaugeOpts{Name: "prover_backend_cached_keys", Help: "Prepared Aeglos keys"})
	engineMemory   = promauto.NewGauge(prometheus.GaugeOpts{Name: "prover_backend_device_bytes", Help: "Native bytes held by the Aeglos engine"})
	engineErrors   = promauto.NewCounter(prometheus.CounterOpts{Name: "prover_backend_errors_total", Help: "Aeglos proof backend errors"})
)

func observe(backend string) func(aeglos.StageTimings) {
	return func(stages aeglos.StageTimings) {
		for _, stage := range []struct {
			name     string
			duration time.Duration
		}{
			{"admission", stages.Admission}, {"prepare", stages.Preparation}, {"witness", stages.Witness},
			{"host_hints", stages.HostHints}, {"commitment", stages.Commitment}, {"fft", stages.FFT},
			{"msm", stages.MSM}, {"proof", stages.Proof}, {"total", stages.Total},
		} {
			engineDuration.WithLabelValues(backend, stage.name).Observe(stage.duration.Seconds())
		}
		result := "miss"
		if stages.CacheHit {
			result = "hit"
		}
		engineCache.WithLabelValues(result).Inc()
		engineKeys.Set(float64(stages.CachedKeys))
		engineMemory.Set(float64(stages.DeviceBytes))
		if stages.Err != nil {
			engineErrors.Inc()
		}
	}
}
