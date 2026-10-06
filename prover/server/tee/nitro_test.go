package tee

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

type fakeNSM struct {
	answer   response.Response
	requests []*request.Attestation
}

func (f *fakeNSM) Send(r request.Request) (response.Response, error) {
	f.requests = append(f.requests, r.(*request.Attestation))
	return f.answer, nil
}

func nitroServer(t *testing.T, answer response.Response) (*Server, *fakeNSM) {
	t.Helper()
	nsm := &fakeNSM{answer: answer}
	s, err := New(context.Background(), Config{Attester: &nitro{nsm: nsm}})
	if err != nil {
		t.Fatal(err)
	}
	return s, nsm
}

func TestNitroAttestationHandler(t *testing.T) {
	document := []byte{0xd2, 0x84, 0x44}
	s, nsm := nitroServer(t, response.Response{Attestation: &response.Attestation{Document: document}})

	nonce := strings.Repeat("22", NonceSize)
	attestation := serveAttestation(t, s, nonce, "document")
	if attestation.Platform != "aws-nitro" || attestation.HPKEPublicKey != hex.EncodeToString(s.PublicKey()) || attestation.GPU != nil {
		t.Fatalf("platform %s key %s gpu %v", attestation.Platform, attestation.HPKEPublicKey, attestation.GPU)
	}
	var evidence nitroEvidence
	if err := json.Unmarshal(attestation.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Document != hex.EncodeToString(document) {
		t.Fatalf("document %s", evidence.Document)
	}

	if len(nsm.requests) != 1 {
		t.Fatalf("%d NSM requests", len(nsm.requests))
	}
	sent := nsm.requests[0]
	reportData := ReportData(mustHex(t, nonce), s.PublicKey(), nil)
	if !bytes.Equal(sent.UserData, reportData[:]) || !bytes.Equal(sent.Nonce, mustHex(t, nonce)) || !bytes.Equal(sent.PublicKey, s.PublicKey()) {
		t.Fatalf("NSM request %+v", sent)
	}
}

func TestNitroDrawsAKeyPerBoot(t *testing.T) {
	first, _ := nitroServer(t, response.Response{})
	second, _ := nitroServer(t, response.Response{})
	if bytes.Equal(first.PublicKey(), second.PublicKey()) {
		t.Fatal("two boots attest the same key")
	}
}

func TestNitroRefusesGPU(t *testing.T) {
	_, err := New(context.Background(), Config{Attester: &nitro{nsm: &fakeNSM{}}, UsesGPU: true})
	if err == nil || !strings.Contains(err.Error(), "aws-nitro attests no GPU") {
		t.Fatalf("err %v", err)
	}
}

func TestNitroRejectsMissingDocument(t *testing.T) {
	for name, answer := range map[string]response.Response{
		"error code": {Error: response.ECInvalidArgument, Attestation: &response.Attestation{Document: []byte{1}}},
		"no answer":  {},
		"empty":      {Attestation: &response.Attestation{}},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := nitroServer(t, answer)
			recorder := httptest.NewRecorder()
			s.AttestationHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, AttestationPath+"?nonce="+strings.Repeat("22", NonceSize), nil))
			if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "attestation_unavailable") {
				t.Fatalf("status %d body %s", recorder.Code, recorder.Body)
			}
		})
	}
}
