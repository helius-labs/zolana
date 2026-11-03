package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// chunked hides its length, as a chunked upload does.
type chunked struct{ io.Reader }

func TestBodyIsRefusedPastItsLimit(t *testing.T) {
	admission := newBodyAdmission(1)
	for name, request := range map[string]*http.Request{
		"declared length": httptest.NewRequest(http.MethodPost, "/prove", bytes.NewReader(make([]byte, 65))),
		"chunked":         httptest.NewRequest(http.MethodPost, "/prove", chunked{bytes.NewReader(make([]byte, 65))}),
	} {
		if (name == "chunked") != (request.ContentLength == -1) {
			t.Fatalf("%s: declared length %d", name, request.ContentLength)
		}
		_, failure := admission.read(httptest.NewRecorder(), request, 64)
		if failure == nil || failure.StatusCode != http.StatusRequestEntityTooLarge || failure.Code != "body_too_large" {
			t.Fatalf("%s: %+v", name, failure)
		}
	}
	body, failure := admission.read(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader("{}")), 64)
	if failure != nil || string(body) != "{}" {
		t.Fatalf("a body within its limit: %q %+v", body, failure)
	}
}

// Bodies are bounded in number as well as size, before any is read: the size
// limit alone lets many concurrent bodies add up.
func TestBodyReadsAreBoundedInNumber(t *testing.T) {
	admission := newBodyAdmission(1)
	admission.permits <- struct{}{}
	_, failure := admission.read(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader("{}")), 64)
	if failure == nil || failure.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a read past the bound: %+v", failure)
	}
	<-admission.permits
	if _, failure := admission.read(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader("{}")), 64); failure != nil {
		t.Fatalf("a read within the bound: %+v", failure)
	}
	if len(admission.permits) != 0 {
		t.Fatal("a finished read kept its permit")
	}
}

// A complete-proof path is bounded by the largest body its key needs, and a
// path without a key by the largest any key needs.
func TestBodyLimitFollowsThePathKey(t *testing.T) {
	transfer := maxBodyBytes("transfer_confidential_2_2.key")
	largeBatch := maxBodyBytes("batch_address-append_40_4999.key")
	if transfer != maxProofBodyBytes || maxBodyBytes("batch_address-append_40_10.key") != batchBodyBytes(40, 10) {
		t.Fatalf("transfer %d", transfer)
	}
	if largeBatch <= transfer || maxBodyBytes("") != largeBatch {
		t.Fatalf("batch %d, keyless %d", largeBatch, maxBodyBytes(""))
	}
}

func TestOversizedProofBodyIsRefusedBeforeParsing(t *testing.T) {
	mux := proofMux(t, nil)
	body := append([]byte(`{"circuitType":"transfer-confidential","x":"`), bytes.Repeat([]byte("a"), maxProofBodyBytes)...)
	response := post(mux, "/prove/transfer_confidential_2_2", body)
	if response.Code != http.StatusRequestEntityTooLarge || errorCode(t, response) != "body_too_large" {
		t.Fatalf("got %d %q", response.Code, response.Body.String())
	}
}
