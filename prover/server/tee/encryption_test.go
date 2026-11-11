package tee

import (
	"bytes"
	"crypto/hpke"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// versions are the wire versions a prover accepts.
var versions = []string{Version1_1, Version1}

// encryptRequest is the client half of the encryption, as the SDKs implement
// it, bound to the request a proxy forwards as uri.
func encryptRequest(t *testing.T, publicKey []byte, version, method, uri string, body []byte) (enc, ciphertext, responseKey []byte) {
	t.Helper()
	binding := bindings[version]
	kem, kdf, aead := suite()
	pk, err := kem.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(pk, kdf, aead, []byte(binding.info))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err = sender.Seal(binding.aad(method, uri), body)
	if err != nil {
		t.Fatal(err)
	}
	responseKey, err = sender.Export(binding.responseExport, responseKeySize)
	if err != nil {
		t.Fatal(err)
	}
	return enc, ciphertext, responseKey
}

func decryptResponse(key, encrypted []byte) (int, []byte, error) {
	gcm, err := responseAEAD(key)
	if err != nil {
		return 0, nil, err
	}
	plaintext, err := gcm.Open(nil, nil, encrypted, nil)
	if err != nil {
		return 0, nil, err
	}
	if len(plaintext) < 2 {
		return 0, nil, errors.New("encrypted response too short")
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

func encryptedRequest(t *testing.T, s *Server, version, method, uri string, body []byte) (*http.Request, []byte) {
	t.Helper()
	enc, ciphertext, responseKey := encryptRequest(t, s.publicKey, version, method, uri, body)
	request := httptest.NewRequest(method, uri, bytes.NewReader(ciphertext))
	if bodiless(method) {
		request = httptest.NewRequest(method, uri, nil)
		request.Header.Set(HeaderCiphertext, hex.EncodeToString(ciphertext))
	}
	request.Header.Set(HeaderVersion, version)
	request.Header.Set(HeaderEnc, hex.EncodeToString(enc))
	request.Header.Set("Content-Type", "application/octet-stream")
	return request, responseKey
}

func TestWrapDecryptsAndEncrypts(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			s := testServer(t)
			request, responseKey := encryptedRequest(t, s, version, http.MethodPost, "/prove/transfer_2_2?api-key=k", []byte(`{"secret":1}`))
			recorder := httptest.NewRecorder()
			s.Wrap(echo(http.StatusTooManyRequests)).ServeHTTP(recorder, request)

			if recorder.Code != http.StatusTooManyRequests {
				t.Fatalf("outer status %d", recorder.Code)
			}
			if recorder.Header().Get(HeaderVersion) != version || recorder.Header().Get("Retry-After") != "3" {
				t.Fatalf("headers %v", recorder.Header())
			}
			if bytes.Contains(recorder.Body.Bytes(), []byte("secret")) {
				t.Fatal("response body is not encrypted")
			}
			status, body, err := decryptResponse(responseKey, recorder.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if status != http.StatusTooManyRequests || string(body) != `POST:application/json:{"secret":1}` {
				t.Fatalf("status %d body %q", status, body)
			}
		})
	}
}

// Clients read /health and /proving-keys through the attested channel too.
func TestWrapEncryptsABodilessGet(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			s := testServer(t)
			request, responseKey := encryptedRequest(t, s, version, http.MethodGet, "/v1/spr/proving-keys?api-key=k", nil)
			recorder := httptest.NewRecorder()
			s.Wrap(echo(http.StatusOK)).ServeHTTP(recorder, request)
			status, body, err := decryptResponse(responseKey, recorder.Body.Bytes())
			if err != nil || status != http.StatusOK || string(body) != "GET:application/json:" {
				t.Fatalf("status %d body %q err %v", status, body, err)
			}
		})
	}
}

func TestWrapRefusesMethodsOtherThanGetAndPost(t *testing.T) {
	s := testServer(t)
	for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for name, inHeader := range map[string]bool{"body": false, "header": true} {
			t.Run(method+" "+name, func(t *testing.T) {
				request, _ := encryptedRequest(t, s, Version1_1, method, "/health", []byte(`{}`))
				if inHeader {
					encrypted, _ := io.ReadAll(request.Body)
					request.Header.Set(HeaderCiphertext, hex.EncodeToString(encrypted))
					request.Body = http.NoBody
				}
				recorder := httptest.NewRecorder()
				reached := false
				s.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(recorder, request)
				assertRejected(t, recorder, reached, codeRequestMalformed)
			})
		}
	}
}

// A handler sees only the method, the route and the decrypted body; headers
// and the query reach the prover unauthenticated. Its answer carries no inner
// header but the retry delay.
func TestWrapHandsOnOnlyWhatTheClientBound(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			s := testServer(t)
			target := GatewayPrefix + "/prove/merge_8_1?async=true&sync=true&api-key=k"
			request, responseKey := encryptedRequest(t, s, version, http.MethodPost, target, []byte(`{}`))
			for _, name := range []string{"X-Async", "X-Sync", "X-Prover-Timing", "X-Request-ID", "Authorization", "X-API-Key"} {
				request.Header.Set(name, "true")
			}
			var seen *http.Request
			recorder := httptest.NewRecorder()
			s.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r
				for _, name := range []string{"Retry-After", "X-Warning", "Server-Timing", "X-Prover-Timing", "X-Request-ID", "Location"} {
					w.Header().Set(name, "1")
				}
				w.WriteHeader(http.StatusTooManyRequests)
			})).ServeHTTP(recorder, request)

			if _, _, err := decryptResponse(responseKey, recorder.Body.Bytes()); err != nil {
				t.Fatal(err)
			}
			if len(seen.Header) != 1 || seen.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("inner headers %v", seen.Header)
			}
			route := GatewayPrefix + "/prove/merge_8_1"
			if seen.URL.RawQuery != "" || seen.RequestURI != route || seen.URL.Path != route {
				t.Fatalf("inner target %q, query %q", seen.RequestURI, seen.URL.RawQuery)
			}
			for name := range recorder.Header() {
				switch name {
				case "Retry-After", HeaderVersion, "Content-Type", "Content-Length":
				default:
					t.Fatalf("inner header %s left the enclave", name)
				}
			}
		})
	}
}

type rejection struct {
	mutate func(*http.Request)
	code   string
}

func TestWrapRejectsRebinding(t *testing.T) {
	cases := map[string]rejection{
		"other key under the gateway": {func(r *http.Request) {
			r.RequestURI = GatewayPrefix + "/prove/merge_8_1/status?jobId=abc"
		}, codeDecryptionFailed},
		"gateway prefix twice": {func(r *http.Request) {
			r.RequestURI = GatewayPrefix + GatewayPrefix + "/prove/transfer_2_2/status?jobId=abc"
		}, codeDecryptionFailed},
		"other method": {func(r *http.Request) { r.Method = http.MethodPost }, codeDecryptionFailed},
		"bad enc":      {func(r *http.Request) { r.Header.Set(HeaderEnc, strings.Repeat("00", 32)) }, codeDecryptionFailed},
		"version":      {func(r *http.Request) { r.Header.Set(HeaderVersion, "v2") }, codeVersionUnsupported},
		"ciphertext in body": {func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(r.Header.Get(HeaderCiphertext)))
			r.Header.Del(HeaderCiphertext)
		}, codeRequestMalformed},
		"missing enc":        {func(r *http.Request) { r.Header.Del(HeaderEnc) }, codeRequestMalformed},
		"non-hex enc":        {func(r *http.Request) { r.Header.Set(HeaderEnc, "zz") }, codeRequestMalformed},
		"short enc":          {func(r *http.Request) { r.Header.Set(HeaderEnc, strings.Repeat("00", encSize-1)) }, codeRequestMalformed},
		"long enc":           {func(r *http.Request) { r.Header.Set(HeaderEnc, strings.Repeat("00", encSize+1)) }, codeRequestMalformed},
		"non-hex ciphertext": {func(r *http.Request) { r.Header.Set(HeaderCiphertext, "zz") }, codeRequestMalformed},
	}
	for _, version := range versions {
		other := Version1
		if version == Version1 {
			other = Version1_1
		}
		for name, c := range cases {
			t.Run(version+" "+name, func(t *testing.T) { assertRebindingRejected(t, version, c) })
		}
		t.Run(version+" sent as "+other, func(t *testing.T) {
			assertRebindingRejected(t, version, rejection{func(r *http.Request) { r.Header.Set(HeaderVersion, other) }, codeDecryptionFailed})
		})
	}
	// v1 binds the query; v1.1 binds the route exactly as sent.
	t.Run("v1 other job", func(t *testing.T) {
		assertRebindingRejected(t, Version1, rejection{func(r *http.Request) {
			r.RequestURI = "/prove/transfer_2_2/status?jobId=other"
		}, codeDecryptionFailed})
	})
	t.Run("v1.1 trailing slash", func(t *testing.T) {
		assertRebindingRejected(t, Version1_1, rejection{func(r *http.Request) {
			r.RequestURI = "/prove/transfer_2_2/status/?jobId=abc"
		}, codeDecryptionFailed})
	})
}

func assertRebindingRejected(t *testing.T, version string, c rejection) {
	t.Helper()
	s := testServer(t)
	request, _ := encryptedRequest(t, s, version, http.MethodGet, "/prove/transfer_2_2/status?jobId=abc", nil)
	c.mutate(request)
	recorder := httptest.NewRecorder()
	reached := false
	s.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(recorder, request)
	assertRejected(t, recorder, reached, c.code)
}

func TestWrapRejectsABodyOverTheCap(t *testing.T) {
	s := testServer(t)
	request, _ := encryptedRequest(t, s, Version1_1, http.MethodPost, "/prove/merge", nil)
	request.Body = io.NopCloser(io.LimitReader(zeros{}, maxEncryptedBody+1))
	request.ContentLength = -1
	recorder := httptest.NewRecorder()
	reached := false
	s.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(recorder, request)
	assertRejected(t, recorder, reached, codeRequestMalformed)
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func assertRejected(t *testing.T, recorder *httptest.ResponseRecorder, reached bool, code string) {
	t.Helper()
	var body struct{ Code string }
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if reached || recorder.Code != http.StatusBadRequest || recorder.Header().Get(HeaderVersion) != "" || body.Code != code {
		t.Fatalf("reached %v status %d code %q, want %q", reached, recorder.Code, body.Code, code)
	}
}

func TestWrapV1IgnoresTheCredentialAProxyMoves(t *testing.T) {
	s := testServer(t)
	for _, name := range []string{"api-key", "api%2Dkey", "%61pi-%6bey", "%61%70%69%2d%6b%65%79"} {
		for _, target := range []string{"/prove/merge/status?jobId=a&api-key=other", "/prove/merge/status?jobId=a"} {
			request, responseKey := encryptedRequest(t, s, Version1, http.MethodGet, "/prove/merge/status?"+name+"=k&jobId=a", nil)
			request.RequestURI = target
			recorder := httptest.NewRecorder()
			s.Wrap(echo(http.StatusOK)).ServeHTTP(recorder, request)
			if _, _, err := decryptResponse(responseKey, recorder.Body.Bytes()); err != nil {
				t.Fatalf("%s: %v", target, err)
			}
		}
	}
}

// A client binds the route below its prover URL, wherever a proxy mounts it.
func TestWrapOpensARouteBareOrUnderTheGatewayPrefix(t *testing.T) {
	for _, version := range versions {
		s := testServer(t)
		for _, target := range []string{"/prove/transfer_2_2?jobId=a", GatewayPrefix + "/prove/transfer_2_2?jobId=a"} {
			request, responseKey := encryptedRequest(t, s, version, http.MethodPost, "/prove/transfer_2_2?jobId=a", []byte(`{}`))
			request.RequestURI = target
			recorder := httptest.NewRecorder()
			s.Wrap(echo(http.StatusOK)).ServeHTTP(recorder, request)
			if _, _, err := decryptResponse(responseKey, recorder.Body.Bytes()); err != nil {
				t.Fatalf("%s %s: %v", version, target, err)
			}
		}
	}
}

// v1.1 binds no query pair, so a proxy may add, move or drop any of them.
func TestWrapV1_1OpensWhateverQueryAProxySends(t *testing.T) {
	s := testServer(t)
	for _, target := range []string{
		"/prove/merge_8_1", "/prove/merge_8_1?api-key=k", "/prove/merge_8_1?",
		GatewayPrefix + "/prove/merge_8_1?jobId=b&async=true&",
	} {
		request, responseKey := encryptedRequest(t, s, Version1_1, http.MethodPost, "/prove/merge_8_1?jobId=a", []byte(`{}`))
		request.RequestURI = target
		recorder := httptest.NewRecorder()
		s.Wrap(echo(http.StatusOK)).ServeHTTP(recorder, request)
		if _, _, err := decryptResponse(responseKey, recorder.Body.Bytes()); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
	}
}

func TestWrapRejectsTamperedBody(t *testing.T) {
	s := testServer(t)
	enc, ciphertext, _ := encryptRequest(t, s.publicKey, Version1_1, http.MethodPost, "/prove/merge", []byte(`{}`))
	ciphertext[0] ^= 1
	request := httptest.NewRequest(http.MethodPost, "/prove/merge", bytes.NewReader(ciphertext))
	request.Header.Set(HeaderVersion, Version1_1)
	request.Header.Set(HeaderEnc, hex.EncodeToString(enc))
	recorder := httptest.NewRecorder()
	reached := false
	s.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(recorder, request)
	assertRejected(t, recorder, reached, codeDecryptionFailed)
}

func TestWrapRefusesPlainWitnessBeforeReadingOrDispatch(t *testing.T) {
	s := testServer(t)
	for _, path := range []string{
		"/prove/merge_8_1", "/prove/merge_8_1/indexed", "/prove",
		"/v1/spr/prove/merge_8_1", "/v1/spr/prove", "/future-proof-route",
	} {
		t.Run(path, func(t *testing.T) {
			body := strings.NewReader(`{"privateWitness":"secret"}`)
			request := httptest.NewRequest(http.MethodPost, path, body)
			recorder := httptest.NewRecorder()
			reached := false
			s.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(recorder, request)
			assertRejected(t, recorder, reached, codeRequired)
			if int64(body.Len()) != body.Size() || strings.Contains(recorder.Body.String(), "secret") {
				t.Fatal("plaintext witness was read or reflected")
			}
		})
	}
}

func TestWrapAllowsOnlyPlainPublicRoutes(t *testing.T) {
	s := testServer(t)
	for _, path := range []string{
		"/auth", "/ready", "/health", "/proving-keys",
		"/v1/spr/proving-keys", AttestationPath, "/v1/spr" + AttestationPath,
	} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			recorder := httptest.NewRecorder()
			s.Wrap(echo(http.StatusOK)).ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK || recorder.Body.String() != "GET::" {
				t.Fatalf("status %d body %q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestReplayedRequestsUseFreshResponseNonces(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			s := testServer(t)
			request, responseKey := encryptedRequest(t, s, Version1_1, method, "/prove/merge/status?jobId=abc", nil)
			ciphertext, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			bodies := []string{"known status response", "known status response", "secret proof response"}
			servers := []*Server{s, s, testServer(t)}
			responses := make([][]byte, len(bodies))
			for i, body := range bodies {
				replay := request.Clone(request.Context())
				replay.Body = io.NopCloser(bytes.NewReader(ciphertext))
				recorder := httptest.NewRecorder()
				servers[i].Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.WriteString(w, body)
				})).ServeHTTP(recorder, replay)
				responses[i] = recorder.Body.Bytes()
				status, decrypted, err := decryptResponse(responseKey, responses[i])
				if err != nil || status != http.StatusOK || string(decrypted) != body {
					t.Fatalf("response %d did not open", i)
				}
				if len(responses[i]) != 12+2+len(body)+16 {
					t.Fatalf("response %d has invalid framing", i)
				}
				for _, previous := range responses[:i] {
					if bytes.Equal(previous[:12], responses[i][:12]) {
						t.Fatal("replayed request reused a response nonce")
					}
				}
			}
			leaked := make([]byte, len(bodies[2]))
			for i := range leaked {
				leaked[i] = responses[0][14+i] ^ responses[2][14+i] ^ bodies[0][i]
			}
			if string(leaked) == bodies[2] {
				t.Fatal("replayed request exposed the response plaintext")
			}
		})
	}
}

func TestWrapV1AcceptsProxyTrailingSlashNormalization(t *testing.T) {
	s := testServer(t)
	for _, route := range []string{"/v1/spr/prove/sample", "/v1/spr"} {
		for _, suffix := range []string{"", "/", "//"} {
			target := route + suffix + "?id=a%20b"
			request, responseKey := encryptedRequest(t, s, Version1, http.MethodPost, target, []byte(`{"value":1}`))
			request.RequestURI = route + "?id=a%20b"
			request.URL.Path = route
			recorder := httptest.NewRecorder()
			s.Wrap(echo(http.StatusOK)).ServeHTTP(recorder, request)
			if _, _, err := decryptResponse(responseKey, recorder.Body.Bytes()); err != nil {
				t.Fatalf("%s: %v", target, err)
			}
		}
	}
}
