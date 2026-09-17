package indexed

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var preparationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "prover_indexer_preparation_duration_seconds",
	Help:    "Indexer preparation duration including admission and validation",
	Buckets: prometheus.ExponentialBuckets(0.01, 2, 14),
}, []string{"outcome"})

var preparationActive = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "prover_indexer_preparation_active", Help: "Active and waiting indexer preparation requests",
})

func (r *Resolver) Resolve(ctx context.Context, data []byte) (*Resolved, error) {
	start := time.Now()
	preparationActive.Inc()
	defer preparationActive.Dec()
	result, err := r.resolve(ctx, data)
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	preparationDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
	return result, err
}
