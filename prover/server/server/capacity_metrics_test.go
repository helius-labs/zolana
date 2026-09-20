package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCapacityMetricsMatchSharedPermits(t *testing.T) {
	execution := &TransferExecution{admission: newSyncAdmission(2)}
	release, ok := execution.acquireQueued(make(chan struct{}))
	if !ok {
		t.Fatal("admission failed")
	}
	defer release()
	readiness := &Readiness{}
	readiness.MarkReady()
	response := httptest.NewRecorder()
	capacityMetrics(execution, readiness).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, metric := range []string{"prover_transfer_capacity 2", "prover_transfer_active 1", "prover_ready 1"} {
		if !strings.Contains(response.Body.String(), metric) {
			t.Fatalf("missing %s", metric)
		}
	}
}

func TestMemoryMetricsExistBeforeFirstProof(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(processMemoryCollector{})
	metrics, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 1 || len(metrics[0].Metric) != 4 {
		t.Fatalf("unexpected memory metrics %v", metrics)
	}
	for _, metric := range metrics[0].Metric {
		if metric.GetGauge().GetValue() <= 0 {
			t.Fatalf("empty process memory sample %v", metric)
		}
	}
}

func TestAdmissionWaitRecordsCancellationAndSuccess(t *testing.T) {
	admission := newSyncAdmission(1)
	release, err := admission.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	before := testutil.ToFloat64(SyncProofsShedTotal)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := admission.admit(ctx); err == nil {
		t.Fatal("request exceeded capacity")
	}
	if testutil.ToFloat64(SyncProofsShedTotal) != before+1 {
		t.Fatal("cancelled wait did not count as rejection")
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(SyncAdmissionWait)
	metrics, gatherErr := registry.Gather()
	if gatherErr != nil {
		t.Fatal(gatherErr)
	}
	if len(metrics) != 1 || len(metrics[0].Metric) != 2 {
		t.Fatalf("missing admission outcomes %v", metrics)
	}
	for _, metric := range metrics[0].Metric {
		if metric.GetHistogram().GetSampleCount() == 0 || metric.GetHistogram().GetSampleSum() <= 0 {
			t.Fatalf("missing admission timing %v", metric)
		}
	}
}
