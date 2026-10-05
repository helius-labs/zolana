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

// Sealed vectors carry a random HPKE ephemeral, so only
// ZOLANA_TEE_WRITE_VECTORS=1 regenerates them.
type vectors struct {
	IKM             string `json:"ikm"`
	HPKEPublicKey   string `json:"hpke_public_key"`
	Nonce           string `json:"nonce"`
	GPUToken        string `json:"gpu_token"`
	ReportData      string `json:"report_data"`
	ReportDataNoGPU string `json:"report_data_no_gpu"`
	GPUNonce        string `json:"gpu_nonce"`
	Method          string `json:"method"`
	RequestURI      string `json:"request_uri"`
	Enc             string `json:"enc"`
	Ciphertext      string `json:"ciphertext"`
	Plaintext       string `json:"plaintext"`
	ResponseKey     string `json:"response_key"`
	ResponseStatus  int    `json:"response_status"`
	ResponseBody    string `json:"response_body"`
	SealedResponse  string `json:"sealed_response"`
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
		method, uri := "POST", "/v1/zolana/prove/transfer_2_2?api-key=k"
		plaintext := []byte(`{"inputs":["secret"]}`)
		enc, ciphertext, responseKey := sealRequest(t, publicKey, method, uri, plaintext)
		responseBody := []byte(`{"proof":"ok"}`)
		sealed, err := sealResponse(responseKey, 200, responseBody)
		if err != nil {
			t.Fatal(err)
		}
		out, err := json.MarshalIndent(vectors{
			IKM:             hex.EncodeToString(ikm),
			HPKEPublicKey:   hex.EncodeToString(publicKey),
			Nonce:           hex.EncodeToString(nonce),
			GPUToken:        string(gpuToken),
			ReportData:      hex.EncodeToString(reportData[:]),
			ReportDataNoGPU: hex.EncodeToString(reportDataNoGPU[:]),
			GPUNonce:        hex.EncodeToString(gpuNonce[:]),
			Method:          method,
			RequestURI:      uri,
			Enc:             hex.EncodeToString(enc),
			Ciphertext:      hex.EncodeToString(ciphertext),
			Plaintext:       string(plaintext),
			ResponseKey:     hex.EncodeToString(responseKey),
			ResponseStatus:  200,
			ResponseBody:    string(responseBody),
			SealedResponse:  hex.EncodeToString(sealed),
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
		if got != want {
			t.Errorf("%s: got %s want %s", name, got, want)
		}
	}
	expect("ikm", hex.EncodeToString(ikm), v.IKM)
	expect("hpke_public_key", hex.EncodeToString(publicKey), v.HPKEPublicKey)
	expect("report_data", hex.EncodeToString(reportData[:]), v.ReportData)
	expect("report_data_no_gpu", hex.EncodeToString(reportDataNoGPU[:]), v.ReportDataNoGPU)
	expect("gpu_nonce", hex.EncodeToString(gpuNonce[:]), v.GPUNonce)

	_, kdf, aead := suite()
	recipient, err := hpke.NewRecipient(mustHex(t, v.Enc), key, kdf, aead, []byte(hpkeInfo))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := recipient.Open(requestAAD(v.Method, v.RequestURI), mustHex(t, v.Ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	expect("plaintext", string(plaintext), v.Plaintext)
	responseKey, err := recipient.Export(responseExport, responseKeySize)
	if err != nil {
		t.Fatal(err)
	}
	expect("response_key", hex.EncodeToString(responseKey), v.ResponseKey)
	status, body, err := openResponse(responseKey, mustHex(t, v.SealedResponse))
	if err != nil || status != v.ResponseStatus || string(body) != v.ResponseBody {
		t.Fatalf("sealed response: status %d body %q err %v", status, body, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
