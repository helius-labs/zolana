//go:build aeglos

package backend

import (
	"time"

	aeglos "github.com/Atamanov/helius-aeglos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	gpuDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "prover_backend_stage_seconds", Help: "Proof backend stage duration", Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20)}, []string{"backend", "stage"})
	gpuCache    = promauto.NewCounterVec(prometheus.CounterOpts{Name: "prover_backend_cache_requests_total", Help: "Proof backend cache lookups"}, []string{"result"})
	gpuKeys     = promauto.NewGauge(prometheus.GaugeOpts{Name: "prover_backend_cached_keys", Help: "Prepared GPU keys"})
	gpuMemory   = promauto.NewGauge(prometheus.GaugeOpts{Name: "prover_backend_device_bytes", Help: "GPU bytes held by the proof backend"})
	gpuErrors   = promauto.NewCounter(prometheus.CounterOpts{Name: "prover_backend_errors_total", Help: "GPU proof backend errors"})
)

func observeGPU(stages aeglos.StageTimings) {
	for _, stage := range []struct {
		name     string
		duration time.Duration
	}{
		{"admission", stages.Admission}, {"prepare", stages.Preparation}, {"witness", stages.Witness},
		{"host_hints", stages.HostHints}, {"commitment", stages.Commitment}, {"fft", stages.FFT},
		{"msm", stages.MSM}, {"proof", stages.Proof}, {"total", stages.Total},
	} {
		gpuDuration.WithLabelValues("aeglos", stage.name).Observe(stage.duration.Seconds())
	}
	result := "miss"
	if stages.CacheHit {
		result = "hit"
	}
	gpuCache.WithLabelValues(result).Inc()
	gpuKeys.Set(float64(stages.CachedKeys))
	gpuMemory.Set(float64(stages.DeviceBytes))
	if stages.Err != nil {
		gpuErrors.Inc()
	}
}
