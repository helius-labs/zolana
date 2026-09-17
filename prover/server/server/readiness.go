package server

import (
	"net/http"
	"sync/atomic"
)

type Readiness struct{ ready atomic.Bool }

func (r *Readiness) MarkReady() { r.ready.Store(true) }

func (r *Readiness) Ready() bool { return r == nil || r.ready.Load() }

func (r *Readiness) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !r.Ready() {
		http.Error(w, "Proving keys are not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}
