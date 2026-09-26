package indexed

import (
	"context"
	"errors"
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
	preparationDuration.WithLabelValues(preparationOutcome(err)).Observe(time.Since(start).Seconds())
	return result, err
}

func preparationOutcome(err error) string {
	var unregistered *UnregisteredMemberError
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, ErrIndexerNotReady):
		return "not_ready"
	case errors.As(err, &unregistered) && unregistered.mismatch:
		return "mismatch"
	case errors.As(err, &unregistered):
		return "rejected"
	}
	return "error"
}
