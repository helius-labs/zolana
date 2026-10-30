package router

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/helius-labs/zolana/prover/server/tee"
)

const ingress = "isolated-gateway-origin-key"
const regional = "isolated-regional-origin-key"

func TestStatusIsWellFormedBeforeRegistryLoads(t *testing.T) {
	r, err := New(&memorySource{}, ingress, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	defer r.transport.CloseIdleConnections()
	w := httptest.NewRecorder()
	r.Status(w, httptest.NewRequest(http.MethodGet, "http://private.invalid/status", nil))
	var state struct {
		Backends []json.RawMessage `json:"backends"`
		Fresh    bool              `json:"registry_fresh"`
	}
	if json.Unmarshal(w.Body.Bytes(), &state) != nil || state.Backends == nil || state.Fresh {
		t.Fatal("startup status did not represent an empty, unready registry")
	}
}

type memorySource struct {
	mu     sync.Mutex
	data   []byte
	err    bool
	secret string
}

func (s *memorySource) Registry(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err {
		return nil, errors.New("private source error")
	}
	return bytes.Clone(s.data), nil
}
func (s *memorySource) Secret(context.Context, string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err {
		return "", errors.New("private credential error")
	}
	return s.secret, nil
}
func (s *memorySource) set(t *testing.T, value Registry) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.data = data
	s.mu.Unlock()
}

type observed struct {
	method, uri string
	body        []byte
	headers     http.Header
}
type fixture struct {
	server      *httptest.Server
	key         []byte
	ready       atomic.Bool
	wrongKey    atomic.Bool
	plain       atomic.Bool
	drop        atomic.Bool
	unavailable atomic.Bool
	quotes      atomic.Uint64
	calls       chan observed
}

func newFixture(t *testing.T, index byte) *fixture {
	t.Helper()
	f := &fixture{key: bytes.Repeat([]byte{index}, 32), calls: make(chan observed, 32)}
	f.ready.Store(true)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != regional || len(r.Header.Values("X-API-Key")) != 1 {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/ready" {
			if !f.ready.Load() {
				w.WriteHeader(503)
				return
			}
			_, _ = io.WriteString(w, `{"status":"ready"}`)
			return
		}
		if r.URL.Path == tee.GatewayPrefix+attestation {
			f.quotes.Add(1)
			key := f.key
			if f.wrongKey.Load() {
				key = bytes.Repeat([]byte{99}, 32)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"hpke_public_key": hex.EncodeToString(key)})
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.calls <- observed{method: r.Method, uri: r.RequestURI, body: body, headers: r.Header.Clone()}
		if f.unavailable.Load() {
			if !f.plain.Load() {
				w.Header().Set(tee.HeaderVersion, tee.Version)
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"code":"tee_generation_unavailable"}`)
			return
		}
		if f.drop.Load() {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		if !f.plain.Load() {
			w.Header().Set(tee.HeaderVersion, tee.Version)
		}
		w.Header().Set("X-Origin-Private", "must-not-forward")
		_, _ = w.Write([]byte{0, 255, 1, 7})
	}))
	t.Cleanup(f.server.Close)
	return f
}

func setup(t *testing.T) (*Router, *memorySource, Registry, []*fixture) {
	t.Helper()
	config := Registry{SchemaVersion: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	var fixtures []*fixture
	for i, region := range []string{"us-east-1", "eu-north-1", "ap-southeast-1"} {
		f := newFixture(t, byte(i+1))
		fixtures = append(fixtures, f)
		id, err := tee.RecipientID(f.key)
		if err != nil {
			t.Fatal(err)
		}
		config.Generations = append(config.Generations, Generation{
			ID: region, Region: region, RecipientID: id,
			Backends: []Backend{{ID: region, Origin: f.server.URL, APIKeyARN: "arn:aws:secretsmanager:" + region + ":558215002830:secret:test-origin-key"}},
		})
	}
	source := &memorySource{secret: regional}
	source.set(t, config)
	r, err := New(source, ingress, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.transport.CloseIdleConnections)
	if err := r.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.Probe(t.Context())
	return r, source, config, fixtures
}

func call(r *Router, method, path, key string, body io.Reader) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://router.invalid"+tee.GatewayPrefix+path, body)
	request.Header.Set("X-API-Key", ingress)
	if key != "" {
		request.Header.Set(tee.HeaderVersion, tee.Version)
		request.Header.Set(tee.HeaderKeyID, key)
		request.Header.Set(tee.HeaderEnc, strings.Repeat("ef", 32))
		if method == http.MethodGet {
			request.Header.Set(tee.HeaderCiphertext, "ffeebb")
		}
	}
	response := httptest.NewRecorder()
	r.ServeHTTP(response, request)
	return response
}

func TestExactRecipientAndOpaqueTransport(t *testing.T) {
	r, _, config, fixtures := setup(t)
	for i, generation := range config.Generations {
		body := []byte{0, 255, 3, 0, 19}
		request := httptest.NewRequest(http.MethodPost, "http://router.invalid"+tee.GatewayPrefix+"/prove/transfer_2_2/indexed?flag&api%2Dkey=outer-secret&tenant=a%20b&v=%2f&v=%2F&literal=a?b", bytes.NewReader(body))
		request.Header.Set("X-API-Key", ingress)
		request.Header.Set("Authorization", "must-not-forward")
		request.Header.Set(tee.HeaderVersion, tee.Version)
		request.Header.Set(tee.HeaderKeyID, generation.RecipientID)
		request.Header.Set(tee.HeaderEnc, "encapsulation")
		request.Header.Set("X-Sync", "true")
		response := httptest.NewRecorder()
		r.ServeHTTP(response, request)
		if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), []byte{0, 255, 1, 7}) || response.Header().Get(tee.HeaderVersion) != tee.Version || response.Header().Get("X-Origin-Private") != "" {
			t.Fatalf("opaque response was changed: %d", response.Code)
		}
		seen := <-fixtures[i].calls
		if !bytes.Equal(seen.body, body) || seen.uri != tee.GatewayPrefix+"/prove/transfer_2_2/indexed?flag&tenant=a%20b&v=%2f&v=%2F&literal=a?b" || seen.headers.Get("X-API-Key") != regional || seen.headers.Get("Authorization") != "" || seen.headers.Get("X-Sync") != "true" || seen.headers.Get(tee.HeaderKeyID) != generation.RecipientID {
			t.Fatal("origin boundary changed bytes or leaked credentials")
		}
		if response := call(r, http.MethodGet, "/health?scope=a%20b", generation.RecipientID, nil); response.Code != 200 {
			t.Fatal(response.Code)
		}
		seen = <-fixtures[i].calls
		if seen.headers.Get(tee.HeaderCiphertext) != "ffeebb" || seen.uri != tee.GatewayPrefix+"/health?scope=a%20b" {
			t.Fatal("GET ciphertext or query lost")
		}
	}
}

func TestDrainAndSharedRegistry(t *testing.T) {
	r, source, config, fixtures := setup(t)
	other, err := New(source, ingress, "eu-north-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.transport.CloseIdleConnections)
	if err := other.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	other.Probe(t.Context())
	config.Revision++
	config.Generations[0].Draining = true
	source.set(t, config)
	for _, replica := range []*Router{r, other} {
		if err := replica.Refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		before := fixtures[0].quotes.Load()
		if response := call(replica, http.MethodGet, attestation+"?nonce="+strings.Repeat("ab", 32), "", nil); response.Code != 200 {
			t.Fatal(response.Code)
		}
		if fixtures[0].quotes.Load() != before {
			t.Fatal("new attestation reached a draining generation")
		}
		if response := call(replica, http.MethodGet, "/health", config.Generations[0].RecipientID, nil); response.Code != 200 {
			t.Fatal("cached recipient lost its drain route")
		}
		<-fixtures[0].calls
	}
}

func TestHealthLossAndRecipientMismatchRejectBeforeForwarding(t *testing.T) {
	r, _, config, fixtures := setup(t)
	fixtures[0].ready.Store(false)
	fixtures[1].wrongKey.Store(true)
	r.Probe(t.Context())
	for i := 0; i < 2; i++ {
		response := call(r, http.MethodPost, "/prove/transfer_2_2", config.Generations[i].RecipientID, bytes.NewReader([]byte("opaque")))
		if response.Code != 503 || !strings.Contains(response.Body.String(), "tee_generation_unavailable") || len(fixtures[i].calls) != 0 {
			t.Fatal("unhealthy key was forwarded")
		}
	}
	if call(r, http.MethodGet, attestation, "", nil).Code != 200 {
		t.Fatal("healthy region was not selected")
	}
	if call(r, http.MethodGet, "/health", config.Generations[2].RecipientID, nil).Code != 200 {
		t.Fatal("healthy region stopped serving")
	}
}

func TestRejectedRegistryNeverPartiallyReplacesTheActiveMap(t *testing.T) {
	r, source, config, _ := setup(t)
	initial := r.current
	config.Revision++
	config.Generations[0].Backends[0].Origin = "https://user:secret@invalid.example"
	source.set(t, config)
	if !errors.Is(r.Refresh(t.Context()), ErrRegistry) || r.current != initial {
		t.Fatal("invalid registry changed live state")
	}
	source.mu.Lock()
	source.data = append(bytes.Clone(source.data), []byte(" trailing")...)
	source.mu.Unlock()
	if !errors.Is(r.Refresh(t.Context()), ErrRegistry) || r.current != initial {
		t.Fatal("trailing JSON changed live state")
	}
	r.mu.Lock()
	r.current.loaded = time.Now().Add(-registryMaxAge - time.Second)
	r.mu.Unlock()
	if call(r, http.MethodGet, "/health", initial.order[0], nil).Code != 503 {
		t.Fatal("stale registry continued admission")
	}
}

func TestRollbackAndSameRevisionSubstitution(t *testing.T) {
	r, source, config, _ := setup(t)
	config.Revision = 2
	source.set(t, config)
	if err := r.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := r.current
	for _, revision := range []uint64{1, 2} {
		config.Revision = revision
		config.Generations[0].Draining = true
		source.set(t, config)
		if !errors.Is(r.Refresh(t.Context()), ErrRegistry) || r.current != before {
			t.Fatal("registry rollback or substitution accepted")
		}
	}
}

func TestFreshnessBudgetsRejectBeforeForwarding(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*snapshot, *backend, time.Time)
	}{
		{"health-expired", func(_ *snapshot, b *backend, now time.Time) { b.checked = now.Add(-healthMaxAge - time.Second) }},
		{"health-clock-backward", func(_ *snapshot, b *backend, now time.Time) { b.checked = now.Add(time.Minute) }},
		{"registry-stale", func(s *snapshot, _ *backend, now time.Time) { s.loaded = now.Add(-registryMaxAge - time.Second) }},
		{"registry-expired", func(s *snapshot, _ *backend, now time.Time) { s.expires = now.Add(-time.Second) }},
		{"registry-clock-backward", func(s *snapshot, _ *backend, now time.Time) { s.loaded = now.Add(time.Minute) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, _, config, fixtures := setup(t)
			id := config.Generations[0].RecipientID
			test.change(r.current, r.current.keys[id].backends[0], time.Now().UTC())
			response := call(r, http.MethodPost, "/prove/transfer_2_2", id, strings.NewReader("opaque proof request"))
			if response.Code != 503 || !strings.Contains(response.Body.String(), "tee_generation_unavailable") || len(fixtures[0].calls) != 0 {
				t.Fatal("invalid freshness allowed forwarding")
			}
		})
	}
}

func TestNoReplayAfterOriginConsumesProof(t *testing.T) {
	r, _, config, fixtures := setup(t)
	fixtures[0].drop.Store(true)
	response := call(r, http.MethodPost, "/prove/transfer_2_2", config.Generations[0].RecipientID, strings.NewReader("opaque proof request"))
	if response.Code != 502 || strings.Contains(response.Body.String(), "tee_generation_unavailable") || len(fixtures[0].calls) != 1 {
		t.Fatal("consumed request replayed or mislabeled as pre-forward")
	}
	if call(r, http.MethodPost, "/prove/transfer_2_2", config.Generations[0].RecipientID, strings.NewReader("next request")).Code != 503 || len(fixtures[0].calls) != 1 {
		t.Fatal("failed origin stayed eligible")
	}
}

func TestOriginCannotEmitTheReservedPreForwardFailureAfterConsumption(t *testing.T) {
	r, _, config, fixtures := setup(t)
	fixtures[0].plain.Store(true)
	fixtures[0].unavailable.Store(true)
	response := call(r, http.MethodPost, "/prove/transfer_2_2", config.Generations[0].RecipientID, strings.NewReader("opaque proof request"))
	if response.Code != 502 || !strings.Contains(response.Body.String(), "tee_upstream_unavailable") || len(fixtures[0].calls) != 1 {
		t.Fatal("consumed origin request masqueraded as pre-forward recipient loss")
	}
}

func TestEncryptedOrigin503RetainsItsProtocolMarkerAndStatus(t *testing.T) {
	r, _, config, fixtures := setup(t)
	fixtures[0].unavailable.Store(true)
	response := call(r, http.MethodPost, "/prove/transfer_2_2", config.Generations[0].RecipientID, strings.NewReader("opaque proof request"))
	if response.Code != 503 || response.Header().Get(tee.HeaderVersion) != tee.Version || len(fixtures[0].calls) != 1 {
		t.Fatal("marked origin response was changed or replayed")
	}
}

func TestPlaintextSuccessIsNotForwardedAsSuccess(t *testing.T) {
	r, _, config, fixtures := setup(t)
	fixtures[0].plain.Store(true)
	response := call(r, http.MethodGet, "/health", config.Generations[0].RecipientID, nil)
	if response.Code != 502 || bytes.Equal(response.Body.Bytes(), []byte{0, 255, 1, 7}) {
		t.Fatal("plaintext origin success escaped")
	}
}

func TestAdmissionLimitDoesNotMasqueradeAsRecipientLoss(t *testing.T) {
	r, _, config, fixtures := setup(t)
	for n := 0; n < cap(r.slots); n++ {
		r.slots <- struct{}{}
	}
	response := call(r, http.MethodPost, "/prove/key", config.Generations[0].RecipientID, strings.NewReader("opaque"))
	if response.Code != 503 || !strings.Contains(response.Body.String(), "tee_router_overloaded") || len(fixtures[0].calls) != 0 {
		t.Fatal("overload forwarded a body or requested recipient recovery")
	}
}

func TestIngressAndProtocolRejectionsNeverReachOrigin(t *testing.T) {
	r, _, config, fixtures := setup(t)
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("X-API-Key", "wrong") },
		func(r *http.Request) { r.Header.Add("X-API-Key", ingress) },
		func(r *http.Request) { r.Header.Del(tee.HeaderKeyID) },
		func(r *http.Request) { r.Header.Add(tee.HeaderKeyID, config.Generations[0].RecipientID) },
		func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		func(r *http.Request) { r.ContentLength = maxBody + 1 },
		func(r *http.Request) { r.URL.Path = "/other/prove/key" },
		func(r *http.Request) { r.URL.RawPath = "/v1/zolana/prove/%6bey" },
	} {
		request := httptest.NewRequest(http.MethodPost, "http://router.invalid"+tee.GatewayPrefix+"/prove/key", strings.NewReader("opaque"))
		request.Header.Set("X-API-Key", ingress)
		request.Header.Set(tee.HeaderVersion, tee.Version)
		request.Header.Set(tee.HeaderKeyID, config.Generations[0].RecipientID)
		mutate(request)
		response := httptest.NewRecorder()
		r.ServeHTTP(response, request)
		if response.Code < 400 || response.Code >= 500 {
			t.Fatalf("request not refused: %d", response.Code)
		}
	}
	for _, f := range fixtures {
		if len(f.calls) != 0 {
			t.Fatal("rejected request reached an origin")
		}
	}
}

func TestRegistryRejectsAmbiguityAndUnsupportedValues(t *testing.T) {
	_, source, _, _ := setup(t)
	valid := string(source.data)
	for _, data := range []string{
		strings.Replace(valid, `"revision":1`, `"revision":1,"revision":2`, 1),
		strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1),
		strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"unknown":true`, 1),
		strings.Replace(valid, `"revision":1`, `"revision":9007199254740992`, 1),
		valid + "{}",
	} {
		if _, err := decodeRegistry([]byte(data), time.Now()); !errors.Is(err, ErrRegistry) {
			t.Fatal("ambiguous registry accepted")
		}
	}
}
