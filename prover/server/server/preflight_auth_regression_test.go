package server

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// A preflight answered before authentication lets any origin probe a protected
// path without a credential, so the served chain itself is under test.
func TestPreflightWithoutCredentialIsRejected(t *testing.T) {
	t.Setenv("PROVER_API_KEY", "test-secret")

	proverAddress := freeLoopbackAddress(t)
	job := RunEnhanced(&EnhancedConfig{
		ProverAddress:  proverAddress,
		MetricsAddress: freeLoopbackAddress(t),
	}, nil, nil)
	defer func() {
		job.RequestStop()
		job.AwaitStop()
	}()

	awaitServer(t, proverAddress)

	request, err := http.NewRequest(http.MethodOptions, fmt.Sprintf("http://%s/prove", proverAddress), nil)
	if err != nil {
		t.Fatalf("build the preflight request: %v", err)
	}
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Access-Control-Request-Method", "POST")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send the preflight request: %v", err)
	}
	response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status %d for an uncredentialed preflight, got %d", http.StatusUnauthorized, response.StatusCode)
	}
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func awaitServer(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(fmt.Sprintf("http://%s/health", address))
		if err == nil {
			response.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s did not come up", address)
}
