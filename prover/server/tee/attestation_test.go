package tee

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

type fakeGuest struct {
	socket string
	quote  string
	events string

	mu         sync.Mutex
	reportData []string
}

func startFakeGuest(t *testing.T, quote string, events json.RawMessage) *fakeGuest {
	t.Helper()
	dir, err := os.MkdirTemp("", "dstack")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	g := &fakeGuest{socket: filepath.Join(dir, "s"), quote: quote, events: string(events)}
	listener, err := net.Listen("unix", g.socket)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/GetKey", func(w http.ResponseWriter, r *http.Request) {
		var request map[string]string
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request["path"] != keyPath {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"key": strings.Repeat("ab", 32)})
	})
	mux.HandleFunc("/GetQuote", func(w http.ResponseWriter, r *http.Request) {
		var request map[string]string
		_ = json.NewDecoder(r.Body).Decode(&request)
		g.mu.Lock()
		g.reportData = append(g.reportData, request["report_data"])
		g.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"quote": g.quote, "event_log": g.events, "vm_config": `{"cpu_count":24}`})
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Close() })
	return g
}

func startFakePCCS(t *testing.T, c Collateral) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/sgx/certification/v4/pckcrl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("SGX-PCK-CRL-Issuer-Chain", url.QueryEscape(c.PCKCRLIssuerChain))
		_, _ = w.Write(mustHex(t, c.PCKCRL))
	})
	mux.HandleFunc("/tdx/certification/v4/tcb", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("TCB-Info-Issuer-Chain", url.QueryEscape(c.TCBInfoIssuerChain))
		_, _ = w.Write([]byte(`{"tcbInfo":` + c.TCBInfo + `,"signature":"` + c.TCBInfoSignature + `"}`))
	})
	mux.HandleFunc("/tdx/certification/v4/qe/identity", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("SGX-Enclave-Identity-Issuer-Chain", url.QueryEscape(c.QEIdentityIssuerChain))
		_, _ = w.Write([]byte(`{"enclaveIdentity":` + c.QEIdentity + `,"signature":"` + c.QEIdentitySignature + `"}`))
	})
	mux.HandleFunc("/sgx/certification/v4/rootcacrl", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(c.RootCACRL))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestDstackAttestationHandler(t *testing.T) {
	fixture := loadProbeFixture(t)
	want := fixture.evidence(t)
	guest := startFakeGuest(t, want.Quote, want.EventLog)
	pccs := startFakePCCS(t, want.Collateral)
	attester, err := NewDstack(DstackConfig{Socket: guest.socket, PCCSURL: pccs.URL})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(context.Background(), Config{Attester: attester})
	if err != nil {
		t.Fatal(err)
	}
	expectedKey, err := deriveKey(mustHex(t, strings.Repeat("ab", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s.PublicKey()) != hex.EncodeToString(expectedKey.PublicKey().Bytes()) {
		t.Fatal("server key is not derived from the KMS secret")
	}

	nonce := strings.Repeat("22", NonceSize)
	attestation := serveAttestation(t, s, nonce, "quote", "event_log", "vm_config", "collateral")
	if attestation.Platform != "dstack-tdx" || attestation.HPKEPublicKey != hex.EncodeToString(s.PublicKey()) || attestation.GPU != nil {
		t.Fatalf("platform %s key %s gpu %v", attestation.Platform, attestation.HPKEPublicKey, attestation.GPU)
	}
	var evidence dstackEvidence
	if err := json.Unmarshal(attestation.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Quote != want.Quote || evidence.VMConfig != `{"cpu_count":24}` {
		t.Fatal("evidence does not carry the guest quote")
	}
	if evidence.Collateral != want.Collateral {
		t.Fatal("collateral does not round trip through the PCCS fetch")
	}
	reportData := ReportData(mustHex(t, nonce), s.PublicKey(), nil)
	if len(guest.reportData) != 1 || guest.reportData[0] != hex.EncodeToString(reportData[:]) {
		t.Fatalf("quote requested for report_data %v", guest.reportData)
	}
}

// serveAttestation fails unless the answer carries exactly the contract fields.
func serveAttestation(t *testing.T, s *Server, nonce string, evidenceFields ...string) Attestation {
	t.Helper()
	recorder := httptest.NewRecorder()
	s.AttestationHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, AttestationPath+"?nonce="+nonce, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body)
	}
	requireFields(t, recorder.Body.Bytes(), "platform", "hpke_public_key", "gpu", "evidence")
	var attestation Attestation
	if err := json.Unmarshal(recorder.Body.Bytes(), &attestation); err != nil {
		t.Fatal(err)
	}
	requireFields(t, attestation.Evidence, evidenceFields...)
	return attestation
}

func requireFields(t *testing.T, raw []byte, want ...string) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(fields)); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
		t.Fatalf("fields %v, want %v", got, want)
	}
}

func TestAttestationHandlerRejectsBadNonce(t *testing.T) {
	s := testServer(t)
	for _, query := range []string{"", "?nonce=zz", "?nonce=" + strings.Repeat("00", 31)} {
		recorder := httptest.NewRecorder()
		s.AttestationHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, AttestationPath+query, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%q: status %d", query, recorder.Code)
		}
	}
}

func TestPCKPlatformOfFixture(t *testing.T) {
	evidence := loadProbeFixture(t).evidence(t)
	chain, err := pckChain(mustHex(t, evidence.Quote))
	if err != nil {
		t.Fatal(err)
	}
	platform, err := pckPlatformOf(chain)
	if err != nil {
		t.Fatal(err)
	}
	var tcb struct {
		FMSPC string `json:"fmspc"`
	}
	if err := json.Unmarshal([]byte(evidence.Collateral.TCBInfo), &tcb); err != nil {
		t.Fatal(err)
	}
	if platform.fmspc != tcb.FMSPC {
		t.Fatalf("fmspc %s, collateral is for %s", platform.fmspc, tcb.FMSPC)
	}
	if _, err := pckChain(mustHex(t, evidence.Quote)[:700]); err == nil {
		t.Fatal("truncated quote parsed")
	}
}
