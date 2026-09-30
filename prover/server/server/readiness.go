package server

import (
	"net/http"
	"sync"
)

type Readiness struct {
	done      chan struct{}
	markReady func()
}

func NewReadiness() *Readiness {
	done := make(chan struct{})
	return &Readiness{done: done, markReady: sync.OnceFunc(func() { close(done) })}
}

func (r *Readiness) MarkReady() { r.markReady() }

func (r *Readiness) Done() <-chan struct{} { return r.done }

func (r *Readiness) Ready() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

func (r *Readiness) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !r.Ready() {
		keysNotReady().send(w)
		return
	}
	w.WriteHeader(http.StatusOK)
}
