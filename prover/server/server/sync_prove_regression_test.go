package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"zolana/prover/prover/common"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// batchAppendSyncBody parses as a valid address-append request whose proving
// key is pinned in the lockfile, so a prove attempt reaches the key loader.
const batchAppendSyncBody = `{"circuitType":"address-append","treeHeight":40,"batchSize":10,` +
	`"publicInputHash":"0x1","oldRoot":"0x1","newRoot":"0x1","hashchainHash":"0x1","startIndex":0}`

// The nil key manager panics as soon as a prove starts, so the panic counter
// is the evidence of a proof attempt for an already abandoned request.
func TestCancelledRequestNeverStartsAProof(t *testing.T) {
	const circuit = "address-append"
	before := testutil.ToFloat64(ProofPanicsTotal.WithLabelValues(circuit))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handler := proveHandler{maxRequestBodyBytes: DefaultMaxRequestBodyBytes}
	request := httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader(batchAppendSyncBody)).WithContext(ctx)
	handler.ServeHTTP(httptest.NewRecorder(), request)

	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if testutil.ToFloat64(ProofPanicsTotal.WithLabelValues(circuit)) > before {
			t.Fatal("a proof attempt ran for a request that was cancelled before it started")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// Saturation holds every prover slot with a proof stuck in the key store, so
// one more synchronous request must be turned away toward the async path.
func TestSaturatedSyncPathReturnsBusyWithTheAsyncHint(t *testing.T) {
	store := newHangingKeyStore(t)
	t.Setenv("ZOLANA_PROVING_KEYS_URL", store.URL())

	keyManager := common.NewLazyKeyManager(t.TempDir(), &common.DownloadConfig{MaxRetries: 1, AutoDownload: true})
	handler := proveHandler{keyManager: keyManager, maxRequestBodyBytes: DefaultMaxRequestBodyBytes}

	var saturators sync.WaitGroup
	for range getMaxConcurrency() + 2 {
		saturators.Add(1)
		go func() {
			defer saturators.Done()
			request := httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader(batchAppendSyncBody))
			handler.ServeHTTP(httptest.NewRecorder(), request)
		}()
	}
	defer saturators.Wait()
	defer store.Release()

	store.AwaitFirstDownload(t)
	time.Sleep(500 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader(batchAppendSyncBody)).WithContext(ctx)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d while every prover slot is taken, got %d with body %q",
			http.StatusServiceUnavailable, response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "X-Async") {
		t.Fatalf("expected the busy reply to point at asynchronous mode, got %q", response.Body.String())
	}
}

// hangingKeyStore stands in for the proving-key object store. Downloads block
// until Release, so a proof that reaches the key loader stays in flight.
type hangingKeyStore struct {
	server      *httptest.Server
	firstOnce   sync.Once
	first       chan struct{}
	releaseOnce sync.Once
	release     chan struct{}
}

func newHangingKeyStore(t *testing.T) *hangingKeyStore {
	store := &hangingKeyStore{
		first:   make(chan struct{}),
		release: make(chan struct{}),
	}
	store.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		store.firstOnce.Do(func() { close(store.first) })
		<-store.release
		w.WriteHeader(http.StatusNotFound)
	}))
	// Release must run before Close, which waits for in-flight handlers.
	t.Cleanup(store.server.Close)
	t.Cleanup(store.Release)
	return store
}

func (store *hangingKeyStore) URL() string { return store.server.URL }

func (store *hangingKeyStore) Release() {
	store.releaseOnce.Do(func() { close(store.release) })
}

func (store *hangingKeyStore) AwaitFirstDownload(t *testing.T) {
	t.Helper()
	select {
	case <-store.first:
	case <-time.After(10 * time.Second):
		t.Fatal("no proof reached the key store")
	}
}
