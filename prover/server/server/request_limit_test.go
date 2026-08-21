package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	nullifiertreetest "zolana/prover/prover-test/nullifier_tree"
)

func TestProveHandlerRejectsOversizedRequest(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, int(maxProofRequestBytes)+1)
	request := httptest.NewRequest(http.MethodPost, "/prove", bytes.NewReader(body))
	response := httptest.NewRecorder()

	(proveHandler{}).ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", response.Code)
	}
}

func TestRequestLimitAcceptsLargestAddressBatch(t *testing.T) {
	params, err := nullifiertreetest.BuildTestAddressTree(40, 250, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/prove", bytes.NewReader(body))
	response := httptest.NewRecorder()

	got, err := readProofRequest(response, request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("request body changed")
	}
}
