package tee

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

func TestAttestationHandler(t *testing.T) {
	fixture := loadProbeFixture(t)
	guest := startFakeGuest(t, fixture.Attestation.Quote, fixture.Attestation.EventLog)
	pccs := startFakePCCS(t, fixture.Attestation.Collateral)
	s, err := New(context.Background(), Config{Socket: guest.socket, PCCSURL: pccs.URL})
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
	recorder := httptest.NewRecorder()
	s.AttestationHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, AttestationPath+"?nonce="+nonce, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body)
	}
	var attestation Attestation
	if err := json.Unmarshal(recorder.Body.Bytes(), &attestation); err != nil {
		t.Fatal(err)
	}
	if attestation.Collateral != fixture.Attestation.Collateral {
		t.Fatal("collateral does not round trip through the PCCS fetch")
	}
	if attestation.HPKEPublicKey != hex.EncodeToString(s.PublicKey()) || attestation.GPU != nil {
		t.Fatalf("key %s gpu %v", attestation.HPKEPublicKey, attestation.GPU)
	}
	want := ReportData(mustHex(t, nonce), s.PublicKey(), nil)
	if len(guest.reportData) != 1 || guest.reportData[0] != hex.EncodeToString(want[:]) {
		t.Fatalf("quote requested for report_data %v", guest.reportData)
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
	fixture := loadProbeFixture(t)
	chain, err := pckChain(mustHex(t, fixture.Attestation.Quote))
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
	if err := json.Unmarshal([]byte(fixture.Attestation.Collateral.TCBInfo), &tcb); err != nil {
		t.Fatal(err)
	}
	if platform.fmspc != tcb.FMSPC {
		t.Fatalf("fmspc %s, collateral is for %s", platform.fmspc, tcb.FMSPC)
	}
	if _, err := pckChain(mustHex(t, fixture.Attestation.Quote)[:700]); err == nil {
		t.Fatal("truncated quote parsed")
	}
}
