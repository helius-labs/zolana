package tee

import (
	"bytes"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Encrypted vectors carry a random HPKE ephemeral, so only
// ZOLANA_TEE_WRITE_VECTORS=1 regenerates them. The top level pins v1.1, which
// the clients send; v1 pins what released clients still send.
type vectors struct {
	IKM               string    `json:"ikm"`
	HPKEPublicKey     string    `json:"hpke_public_key"`
	Nonce             string    `json:"nonce"`
	GPUToken          string    `json:"gpu_token"`
	ReportData        string    `json:"report_data"`
	ReportDataNoGPU   string    `json:"report_data_no_gpu"`
	GPUNonce          string    `json:"gpu_nonce"`
	Version           string    `json:"version"`
	Method            string    `json:"method"`
	Route             string    `json:"route"`
	AAD               string    `json:"aad"`
	Enc               string    `json:"enc"`
	Ciphertext        string    `json:"ciphertext"`
	Plaintext         string    `json:"plaintext"`
	ResponseKey       string    `json:"response_key"`
	ResponseStatus    int       `json:"response_status"`
	ResponseBody      string    `json:"response_body"`
	EncryptedResponse string    `json:"encrypted_response"`
	AADCases          []aadCase `json:"aad_cases"`
	V1                v1Vectors `json:"v1"`
}

type v1Vectors struct {
	Method      string    `json:"method"`
	RequestURI  string    `json:"request_uri"`
	Enc         string    `json:"enc"`
	Ciphertext  string    `json:"ciphertext"`
	Plaintext   string    `json:"plaintext"`
	ResponseKey string    `json:"response_key"`
	AADCases    []aadCase `json:"aad_cases"`
}

// aadCase is the AAD a prover opens a request with, from the target a proxy
// forwarded it to.
type aadCase struct {
	Method        string `json:"method"`
	RequestTarget string `json:"request_target"`
	AAD           string `json:"aad"`
}

// aadTargets cover the gateway prefix, the query a v1.1 call never binds, and
// the paths it binds exactly as sent.
var aadTargets = [][2]string{
	{"GET", "/health"},
	{"GET", "/v1/spr/proving-keys?api-key=k"},
	{"POST", "/prove/transfer_2_2"},
	{"POST", "/v1/spr/prove/transfer_2_2?api-key=k&jobId=a&async=true"},
	{"POST", "/v1/spr/prove/merge_8_1/indexed"},
	{"POST", "/prove/transfer_2_2/"},
	{"POST", "/prove/sample%2F"},
	{"POST", "/v1/spr/v1/spr/prove/x"},
	{"POST", "/v1/sprx/prove/x"},
	{"GET", "/v1/spr?jobId=a"},
	{"GET", "/v1/spr/"},
}

// aadTargetsV1 cover where a proxy may put, repeat or drop the credential, and
// which paths drop the gateway prefix.
var aadTargetsV1 = [][2]string{
	{"GET", "/"},
	{"POST", "/v1/spr/prove/sample/?id=a%20b"},
	{"POST", "/prove/sample//?id=a%20b"},
	{"POST", "/prove/sample%2F/?id=a%20b"},
	{"GET", "/v1/spr/?jobId=a"},
	{"GET", "/v1/spr//"},
	{"GET", "/health"},
	{"POST", "/v1/spr/prove/transfer_2_2?api-key=k"},
	{"POST", "/v1/spr/v1/spr/prove/x"},
	{"POST", "/v1/sprx/prove/x"},
	{"GET", "/v1/spr?jobId=a"},
	{"GET", "/prove/merge_8_1/status?api-key=k&jobId=a1"},
	{"GET", "/prove/merge_8_1/status?jobId=a1&api-key=k"},
	{"GET", "/attestation?nonce=ab&api-key=k1&api-key=k2"},
	{"GET", "/prove/x?api-keys=v&api-key"},
	{"GET", "/prove/x?&&jobId=a&"},
	{"POST", "/v1/spr/prove/transfer_2_2?api%2Dkey=k&jobId=%61%31&q=a%20b+c"},
	{"GET", "/prove/x?%61pi-key=a&api-%6Bey=b&%61%70%69%2d%6b%65%79=c&jobId=a"},
	{"GET", "/prove/x?api-key=k&API-KEY=keep&api+key=keep&api%2Bkey=keep&bad%=keep"},
	{"GET", "/prove/x??api-key=keep&jobId=a"},
}

func aadCases(version string, targets [][2]string) []aadCase {
	cases := make([]aadCase, len(targets))
	for i, target := range targets {
		cases[i] = aadCase{Method: target[0], RequestTarget: target[1], AAD: string(bindings[version].aad(target[0], target[1]))}
	}
	return cases
}

func TestVectors(t *testing.T) {
	path := filepath.Join(testdata, "vectors.json")
	ikm := bytes.Repeat([]byte{0x5a}, 32)
	nonce := bytes.Repeat([]byte{0x11}, NonceSize)
	gpuToken := []byte(`[["JWT","header.payload.signature"],{"GPU-0":"device"}]`)
	key, err := deriveKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := key.PublicKey().Bytes()
	reportData := ReportData(nonce, publicKey, gpuToken)
	reportDataNoGPU := ReportData(nonce, publicKey, nil)
	gpuNonce := GPUNonce(nonce, publicKey)

	if os.Getenv("ZOLANA_TEE_WRITE_VECTORS") != "" {
		method, route := "POST", "/prove/transfer_2_2"
		plaintext := []byte(`{"inputs":["secret"]}`)
		enc, ciphertext, responseKey := encryptRequest(t, publicKey, Version1_1, method, route, plaintext)
		responseBody := []byte(`{"proof":"ok"}`)
		encrypted, err := encryptResponse(responseKey, 200, responseBody)
		if err != nil {
			t.Fatal(err)
		}
		uriV1 := "/v1/spr/prove/transfer_2_2?api-key=k"
		encV1, ciphertextV1, responseKeyV1 := encryptRequest(t, publicKey, Version1, method, uriV1, plaintext)
		out, err := json.MarshalIndent(vectors{
			IKM:               hex.EncodeToString(ikm),
			HPKEPublicKey:     hex.EncodeToString(publicKey),
			Nonce:             hex.EncodeToString(nonce),
			GPUToken:          string(gpuToken),
			ReportData:        hex.EncodeToString(reportData[:]),
			ReportDataNoGPU:   hex.EncodeToString(reportDataNoGPU[:]),
			GPUNonce:          hex.EncodeToString(gpuNonce[:]),
			Version:           Version1_1,
			Method:            method,
			Route:             route,
			AAD:               string(requestAAD(method, route)),
			Enc:               hex.EncodeToString(enc),
			Ciphertext:        hex.EncodeToString(ciphertext),
			Plaintext:         string(plaintext),
			ResponseKey:       hex.EncodeToString(responseKey),
			ResponseStatus:    200,
			ResponseBody:      string(responseBody),
			EncryptedResponse: hex.EncodeToString(encrypted),
			AADCases:          aadCases(Version1_1, aadTargets),
			V1: v1Vectors{
				Method:      method,
				RequestURI:  uriV1,
				Enc:         hex.EncodeToString(encV1),
				Ciphertext:  hex.EncodeToString(ciphertextV1),
				Plaintext:   string(plaintext),
				ResponseKey: hex.EncodeToString(responseKeyV1),
				AADCases:    aadCases(Version1, aadTargetsV1),
			},
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	expect := func(name, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("%s: got %s want %s", name, got, want)
		}
	}
	expect("ikm", hex.EncodeToString(ikm), v.IKM)
	expect("hpke_public_key", hex.EncodeToString(publicKey), v.HPKEPublicKey)
	expect("report_data", hex.EncodeToString(reportData[:]), v.ReportData)
	expect("report_data_no_gpu", hex.EncodeToString(reportDataNoGPU[:]), v.ReportDataNoGPU)
	expect("gpu_nonce", hex.EncodeToString(gpuNonce[:]), v.GPUNonce)
	expect("version", Version1_1, v.Version)
	expect("aad", string(requestAAD(v.Method, v.Route)), v.AAD)
	expectCases(t, "aad case", aadCases(Version1_1, aadTargets), v.AADCases)
	expectCases(t, "v1 aad case", aadCases(Version1, aadTargetsV1), v.V1.AADCases)

	responseKey := openVector(t, key, Version1_1, v.Method, v.Route, v.Enc, v.Ciphertext, v.Plaintext)
	expect("response_key", hex.EncodeToString(responseKey), v.ResponseKey)
	status, body, err := decryptResponse(responseKey, mustHex(t, v.EncryptedResponse))
	if err != nil || status != v.ResponseStatus || string(body) != v.ResponseBody {
		t.Fatalf("encrypted response: status %d body %q err %v", status, body, err)
	}
	responseKeyV1 := openVector(t, key, Version1, v.V1.Method, v.V1.RequestURI, v.V1.Enc, v.V1.Ciphertext, v.V1.Plaintext)
	expect("v1 response_key", hex.EncodeToString(responseKeyV1), v.V1.ResponseKey)
}

func expectCases(t *testing.T, name string, want, got []aadCase) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s count: got %d want %d", name, len(got), len(want))
	}
	for i, c := range want {
		if i >= len(got) || got[i] != c {
			t.Errorf("%s %d: got %+v", name, i, c)
		}
	}
}

// openVector opens a pinned request as the prover does and returns its
// response key.
func openVector(t *testing.T, key hpke.PrivateKey, version, method, uri, enc, ciphertext, want string) []byte {
	t.Helper()
	binding := bindings[version]
	_, kdf, aead := suite()
	recipient, err := hpke.NewRecipient(mustHex(t, enc), key, kdf, aead, []byte(binding.info))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := recipient.Open(binding.aad(method, uri), mustHex(t, ciphertext))
	if err != nil {
		t.Fatalf("%s request: %v", version, err)
	}
	if string(plaintext) != want {
		t.Fatalf("%s plaintext %q", version, plaintext)
	}
	responseKey, err := recipient.Export(binding.responseExport, responseKeySize)
	if err != nil {
		t.Fatal(err)
	}
	return responseKey
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
