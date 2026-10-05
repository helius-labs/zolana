package tee

import (
	"bytes"
	"crypto/hpke"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sealRequest is the client half of the sealing, as the SDKs implement it.
func sealRequest(t *testing.T, publicKey []byte, method, uri string, body []byte) (enc, ciphertext, responseKey []byte) {
	t.Helper()
	kem, kdf, aead := suite()
	pk, err := kem.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(pk, kdf, aead, []byte(hpkeInfo))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err = sender.Seal(requestAAD(method, uri), body)
	if err != nil {
		t.Fatal(err)
	}
	responseKey, err = sender.Export(responseExport, responseKeySize)
	if err != nil {
		t.Fatal(err)
	}
	return enc, ciphertext, responseKey
}

func openResponse(key, sealed []byte) (int, []byte, error) {
	gcm, err := responseAEAD(key)
	if err != nil {
		return 0, nil, err
	}
	plaintext, err := gcm.Open(nil, make([]byte, gcm.NonceSize()), sealed, nil)
	if err != nil {
		return 0, nil, err
	}
	if len(plaintext) < 2 {
		return 0, nil, errors.New("sealed response too short")
	}
	return int(binary.BigEndian.Uint16(plaintext)), plaintext[2:], nil
}

func testServer(t *testing.T) *Server {
	t.Helper()
	key, err := deriveKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &Server{key: key, publicKey: key.PublicKey().Bytes(), permits: make(chan struct{}, attestationConcurrency)}
}

func echo(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Retry-After", "3")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(r.Method + ":" + r.Header.Get("Content-Type") + ":" + string(body)))
	})
}

func sealedRequest(t *testing.T, s *Server, method, uri string, body []byte) (*http.Request, []byte) {
	t.Helper()
	enc, ciphertext, responseKey := sealRequest(t, s.publicKey, method, uri, body)
	request := httptest.NewRequest(method, uri, bytes.NewReader(ciphertext))
	request.Header.Set(HeaderVersion, Version)
	request.Header.Set(HeaderEnc, hex.EncodeToString(enc))
	request.Header.Set("Content-Type", "application/octet-stream")
	return request, responseKey
}

func TestWrapOpensAndSeals(t *testing.T) {
	s := testServer(t)
	request, responseKey := sealedRequest(t, s, http.MethodPost, "/prove/transfer_2_2?api-key=k", []byte(`{"secret":1}`))
	recorder := httptest.NewRecorder()
	s.Wrap(echo(http.StatusTooManyRequests)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("outer status %d", recorder.Code)
	}
	if recorder.Header().Get(HeaderVersion) != Version || recorder.Header().Get("Retry-After") != "3" {
		t.Fatalf("headers %v", recorder.Header())
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("secret")) {
		t.Fatal("response body is not sealed")
	}
	status, body, err := openResponse(responseKey, recorder.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusTooManyRequests || string(body) != `POST:application/json:{"secret":1}` {
		t.Fatalf("status %d body %q", status, body)
	}
}

func TestWrapSealsBodilessPoll(t *testing.T) {
	s := testServer(t)
	request, responseKey := sealedRequest(t, s, http.MethodGet, "/prove/transfer_2_2/status?jobId=abc", nil)
	recorder := httptest.NewRecorder()
	s.Wrap(echo(http.StatusOK)).ServeHTTP(recorder, request)
	status, body, err := openResponse(responseKey, recorder.Body.Bytes())
	if err != nil || status != http.StatusOK || string(body) != "GET:application/json:" {
		t.Fatalf("status %d body %q err %v", status, body, err)
	}
}

func TestWrapRejectsRebinding(t *testing.T) {
	s := testServer(t)
	cases := map[string]func(*http.Request){
		"other job":    func(r *http.Request) { r.RequestURI = "/prove/transfer_2_2/status?jobId=other" },
		"other method": func(r *http.Request) { r.Method = http.MethodPut },
		"bad enc":      func(r *http.Request) { r.Header.Set(HeaderEnc, strings.Repeat("00", 32)) },
		"version":      func(r *http.Request) { r.Header.Set(HeaderVersion, "v2") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request, _ := sealedRequest(t, s, http.MethodGet, "/prove/transfer_2_2/status?jobId=abc", nil)
			mutate(request)
			recorder := httptest.NewRecorder()
			reached := false
			s.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(recorder, request)
			if reached || recorder.Code != http.StatusBadRequest || recorder.Header().Get(HeaderVersion) != "" {
				t.Fatalf("reached %v status %d", reached, recorder.Code)
			}
		})
	}
}

func TestWrapRejectsTamperedBody(t *testing.T) {
	s := testServer(t)
	enc, ciphertext, _ := sealRequest(t, s.publicKey, http.MethodPost, "/prove/merge", []byte(`{}`))
	ciphertext[0] ^= 1
	request := httptest.NewRequest(http.MethodPost, "/prove/merge", bytes.NewReader(ciphertext))
	request.Header.Set(HeaderVersion, Version)
	request.Header.Set(HeaderEnc, hex.EncodeToString(enc))
	recorder := httptest.NewRecorder()
	s.Wrap(echo(http.StatusOK)).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d", recorder.Code)
	}
}

func TestWrapPassesPlainRequests(t *testing.T) {
	s := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "/prove/merge", strings.NewReader("plain"))
	request.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	s.Wrap(echo(http.StatusOK)).ServeHTTP(recorder, request)
	if recorder.Body.String() != "POST:text/plain:plain" || recorder.Header().Get(HeaderVersion) != "" {
		t.Fatalf("body %q", recorder.Body.String())
	}
}
