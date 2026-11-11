// Package tee serves confidential computing attestation and encrypts prover
// traffic to the attested HPKE key, in the byte layouts prover/tee/testdata
// pins for the Rust and TypeScript clients.
package tee

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/sha512"
	"net/url"
	"strings"
)

const (
	// Version1_1 binds the method and the route of an encrypted call.
	Version1_1 = "v1.1"
	// Version1 also binds the query. Released clients send it, so a prover
	// accepts it until they have moved to Version1_1.
	Version1      = "v1"
	HeaderVersion = "Spr-Tee"
	HeaderEnc     = "Spr-Tee-Enc"
	// HeaderCiphertext carries the encrypted bytes of a GET, fetch refuses a GET body.
	HeaderCiphertext = "Spr-Tee-Ciphertext"
	NonceSize        = 32
	// GatewayPrefix is the path the Helius gateway serves the prover under.
	// Every route under it runs the same handler as the bare route.
	GatewayPrefix = "/v1/spr"

	// Domain separation for every hash and HPKE context the protocol binds.
	reportDomain = "zolana/prover-tee/v1/report"
	gpuDomain    = "zolana/prover-tee/v1/gpu"

	responseKeySize = 32
	apiKeyParam     = "api-key"
	gcmTagSize      = 16
)

// binding is what one wire version feeds HPKE. Each version has its own info,
// so a request sealed under one version never opens under the other's AAD.
type binding struct {
	info           string
	responseExport string
	aad            func(method, requestURI string) []byte
}

var bindings = map[string]binding{
	Version1_1: {info: "zolana/prover-tee/v1.1", responseExport: "zolana/prover-tee/v1.1/response", aad: requestAAD},
	Version1:   {info: "zolana/prover-tee/v1", responseExport: "zolana/prover-tee/v1/response", aad: requestAADv1},
}

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

// requestAAD binds the method and the route as received, after one leading
// GatewayPrefix: a client binds the path below the prover URL it was given, so
// a proxy can serve the prover bare or under the prefix. The query is not
// bound and Wrap never passes it to a handler, so a proxy can add, move or
// drop any pair.
func requestAAD(method, requestURI string) []byte {
	path, _, _ := strings.Cut(requestURI, "?")
	return []byte(method + " " + belowGateway(path))
}

func belowGateway(path string) string {
	if route, ok := strings.CutPrefix(path, GatewayPrefix); ok && strings.HasPrefix(route, "/") {
		return route
	}
	return path
}

// requestAADv1 binds the method, route and query minus every api-key
// parameter, so a proxy can move the credential while the route and job stay
// bound. The route drops trailing slashes and then GatewayPrefix, in the
// order a gateway trims and forwards.
func requestAADv1(method, requestURI string) []byte {
	path, query, _ := strings.Cut(requestURI, "?")
	path = belowGateway(strings.TrimRight(path, "/"))
	if path == "" {
		path = "/"
	}
	var kept []string
	for _, pair := range strings.Split(query, "&") {
		key, _, _ := strings.Cut(pair, "=")
		decoded, err := url.QueryUnescape(key)
		if pair == "" || (err == nil && decoded == apiKeyParam) {
			continue
		}
		kept = append(kept, pair)
	}
	if len(kept) == 0 {
		return []byte(method + " " + path)
	}
	return []byte(method + " " + path + "?" + strings.Join(kept, "&"))
}
