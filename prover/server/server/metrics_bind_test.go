package server

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func TestMetricsBindFailureDoesNotPanic(t *testing.T) {
	t.Parallel()

	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold port: %v", err)
	}
	defer holder.Close()

	job := spawnMetricsServerJob(&http.Server{
		Addr:    holder.Addr().String(),
		Handler: http.NewServeMux(),
	})
	// Give the start goroutine a moment; a panic would fail the test process.
	time.Sleep(50 * time.Millisecond)
	job.RequestStop()
	job.AwaitStop()
}

func TestMetricsServesWhenPortFree(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve addr: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	job := spawnMetricsServerJob(&http.Server{Addr: addr, Handler: mux})
	defer func() {
		job.RequestStop()
		job.AwaitStop()
	}()

	deadline := time.Now().Add(2 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		resp, getErr := http.Get("http://" + addr + "/metrics")
		if getErr == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			last = nil
		} else {
			last = getErr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("metrics never became ready: %v", last)
}
