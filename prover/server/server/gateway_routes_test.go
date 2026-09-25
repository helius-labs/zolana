package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Gatekeeper forwards the request path verbatim, so every route published
// through the gateway has to resolve under the prefix as well as bare. A
// regression here is invisible on the ALB and only shows up as a 404 through
// beta-devnet.helius-rpc.com, which is why it is pinned by a test.
func TestHandleBothServesBareAndPrefixedPaths(t *testing.T) {
	mux := http.NewServeMux()
	handleBoth(mux, "/prove", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	for _, path := range []string{"/prove", gatewayPrefix + "/prove"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusTeapot {
			t.Fatalf("%s: got %d, want %d", path, rec.Code, http.StatusTeapot)
		}
	}
}

// The operational surface stays off the public prefix: registering a route
// bare must not publish it under the gateway namespace by accident.
func TestPlainHandleIsNotPublishedUnderPrefix(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/queue/stats", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, gatewayPrefix+"/queue/stats", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusNotFound)
	}
}
