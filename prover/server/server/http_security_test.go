package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProveHandlerRejectsOversizedRequest(t *testing.T) {
	handler := proveHandler{maxRequestBodyBytes: 4}
	request := httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader("12345"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, response.Code)
	}
	if !strings.Contains(response.Body.String(), `"code":"request_too_large"`) {
		t.Fatalf("expected request_too_large response, got %q", response.Body.String())
	}
}

func TestHTTPServerUsesHardenedReadLimits(t *testing.T) {
	server := newHTTPServer("127.0.0.1:0", http.NewServeMux())

	if server.ReadHeaderTimeout != defaultReadHeaderTimeout {
		t.Fatalf("unexpected read-header timeout: %s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != defaultReadTimeout {
		t.Fatalf("unexpected read timeout: %s", server.ReadTimeout)
	}
	if server.IdleTimeout != defaultIdleTimeout {
		t.Fatalf("unexpected idle timeout: %s", server.IdleTimeout)
	}
	if server.MaxHeaderBytes != defaultMaxHeaderBytes {
		t.Fatalf("unexpected maximum header size: %d", server.MaxHeaderBytes)
	}
}

// A write deadline shorter than the synchronous proof deadline would sever a
// proof the handler is still allowed to finish.
func TestHTTPServerWriteTimeoutOutlastsSyncProofs(t *testing.T) {
	server := newHTTPServer("127.0.0.1:0", http.NewServeMux())

	if server.WriteTimeout <= maxSyncProofTimeout {
		t.Fatalf("write timeout %s does not outlast the %s proof deadline", server.WriteTimeout, maxSyncProofTimeout)
	}
}

// An unbounded synchronous path starts one Groth16 prove per request, each
// holding a proving key.
func TestSyncProofsAreBounded(t *testing.T) {
	if slots := cap(syncProofSlots()); slots < MinConcurrencyPerWorker {
		t.Fatalf("synchronous proof slots = %d, want at least %d", slots, MinConcurrencyPerWorker)
	}
}

// A cancelled request must not reach a proving key. The nil key manager panics
// if the prove starts, so the returned error is the evidence it did not.
func TestProcessProofSyncStopsForAnAbandonedRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handler := proveHandler{}
	_, proofError := handler.processProofSync(ctx, []byte(`{"circuitType":"transfer-confidential","nInputs":2,"nOutputs":2}`))

	if proofError == nil {
		t.Fatal("expected an error for a cancelled request")
	}
	if proofError.Code != "request_abandoned" {
		t.Fatalf("expected request_abandoned, got %q", proofError.Code)
	}
}

func TestPublicBindRequiresConfiguredAPIKey(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := conditionalAuthMiddleware("", true)(next)
	request := httptest.NewRequest(http.MethodPost, "/prove", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, response.Code)
	}
	if !strings.Contains(response.Body.String(), `"code":"api_key_required"`) {
		t.Fatalf("expected api_key_required response, got %q", response.Body.String())
	}
}

func TestLoopbackBindDetection(t *testing.T) {
	for _, address := range []string{"127.0.0.1:5000", "localhost:5000", "[::1]:5000"} {
		if !isLoopbackBindAddress(address) {
			t.Fatalf("expected %q to be loopback", address)
		}
	}
	for _, address := range []string{"0.0.0.0:5000", "[::]:5000", ":5000", "bad-address"} {
		if isLoopbackBindAddress(address) {
			t.Fatalf("expected %q to require authentication", address)
		}
	}
}

// The CORS handler answers a preflight on its own, so its position in the chain
// decides whether a protected path can be probed without a credential.
func TestPreflightDoesNotBypassAuth(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := proverHandlerChain("secret", true, next)

	request := httptest.NewRequest(http.MethodOptions, "/prove", nil)
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Access-Control-Request-Method", "POST")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, response.Code)
	}
}

func TestLoopbackProverRejectsBrowserOrigin(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := conditionalAuthMiddleware("", false)(next)
	request := httptest.NewRequest(http.MethodPost, "/prove", nil)
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, response.Code)
	}
	if !strings.Contains(response.Body.String(), `"code":"browser_origin_forbidden"`) {
		t.Fatalf("expected browser_origin_forbidden response, got %q", response.Body.String())
	}
}
