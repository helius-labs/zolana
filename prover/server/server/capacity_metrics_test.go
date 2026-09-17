package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
