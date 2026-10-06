// Package tee serves confidential computing attestation and encrypts prover
// traffic to the attested HPKE key, in the byte layouts prover/tee/testdata
// pins for the Rust and TypeScript clients.
package tee

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/sha512"
	"strings"
)

const (
	Version       = "v1"
	HeaderVersion = "Zolana-Tee"
	HeaderEnc     = "Zolana-Tee-Enc"
	// HeaderCiphertext carries the encrypted bytes of a GET, fetch refuses a GET body.
	HeaderCiphertext = "Zolana-Tee-Ciphertext"
	NonceSize        = 32

	// Domain separation for every hash and HPKE context the protocol binds.
	reportDomain   = "zolana/prover-tee/v1/report"
	gpuDomain      = "zolana/prover-tee/v1/gpu"
	hpkeInfo       = "zolana/prover-tee/v1"
	responseExport = "zolana/prover-tee/v1/response"

	responseKeySize = 32
	apiKeyParam     = "api-key"
	gcmTagSize      = 16
)

func suite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// ReportData binds the client nonce, the encryption key and the NRAS digest into the quote, zeros without a GPU.
func ReportData(nonce, hpkePublicKey, gpuToken []byte) [64]byte {
	var gpuDigest [32]byte
	if gpuToken != nil {
		gpuDigest = sha256.Sum256(gpuToken)
	}
	h := sha512.New()
	h.Write([]byte(reportDomain))
	h.Write(nonce)
	h.Write(hpkePublicKey)
	h.Write(gpuDigest[:])
	var out [64]byte
	h.Sum(out[:0])
	return out
}

// GPUNonce ties the GPU evidence to the same session as the quote.
func GPUNonce(nonce, hpkePublicKey []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(gpuDomain))
	h.Write(nonce)
	h.Write(hpkePublicKey)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// requestAAD binds the method, path and query minus every api-key parameter,
// so a proxy can move the credential while the route and job stay bound.
func requestAAD(method, requestURI string) []byte {
	path, query, _ := strings.Cut(requestURI, "?")
	var kept []string
	for _, pair := range strings.Split(query, "&") {
		if key, _, _ := strings.Cut(pair, "="); pair == "" || key == apiKeyParam {
			continue
		}
		kept = append(kept, pair)
	}
	if len(kept) == 0 {
		return []byte(method + " " + path)
	}
	return []byte(method + " " + path + "?" + strings.Join(kept, "&"))
}
