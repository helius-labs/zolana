package tee

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	nrasAttestURL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
	nrasJWKSURL   = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
)

type gpuEvidence struct {
	Evidence    string `json:"evidence"`
	Certificate string `json:"certificate"`
}

// nras submits GPU evidence and accepts the verdict only after checking its
// signatures, nonce and overall result inside the TEE.
type nras struct {
	attestURL string
	jwksURL   string
	client    *http.Client
	now       func() time.Time

	mu   sync.Mutex
	keys map[string]*ecdsa.PublicKey
}

func newNRAS() *nras {
	return &nras{
		attestURL: nrasAttestURL,
		jwksURL:   nrasJWKSURL,
		client:    &http.Client{Timeout: 60 * time.Second},
		now:       time.Now,
		keys:      map[string]*ecdsa.PublicKey{},
	}
}

func (n *nras) attest(ctx context.Context, arch string, nonce [32]byte, evidence []gpuEvidence) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"nonce":          hex.EncodeToString(nonce[:]),
		"arch":           arch,
		"evidence_list":  evidence,
		"claims_version": "3.0",
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.attestURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("NRAS: %w", err)
	}
	defer response.Body.Close()
	token, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("NRAS: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NRAS: HTTP %d", response.StatusCode)
	}
	if err := n.verify(ctx, token, nonce); err != nil {
		return nil, fmt.Errorf("NRAS verdict rejected: %w", err)
	}
	return token, nil
}

// verify accepts a response only with current NRAS signatures, the session nonce, a true overall result and every device token in submods.
func (n *nras) verify(ctx context.Context, response []byte, nonce [32]byte) error {
	var parts []json.RawMessage
	if err := json.Unmarshal(response, &parts); err != nil || len(parts) != 2 {
		return errors.New("unexpected response shape")
	}
	var platformPair []string
	if err := json.Unmarshal(parts[0], &platformPair); err != nil || len(platformPair) != 2 || platformPair[0] != "JWT" {
		return errors.New("missing platform token")
	}
	var devices map[string]string
	if err := json.Unmarshal(parts[1], &devices); err != nil || len(devices) == 0 {
		return errors.New("missing device tokens")
	}
	var platform struct {
		Overall   *bool                      `json:"x-nvidia-overall-att-result"`
		Nonce     string                     `json:"eat_nonce"`
		Submods   map[string]json.RawMessage `json:"submods"`
		Expiry    int64                      `json:"exp"`
		NotBefore int64                      `json:"nbf"`
	}
	if err := n.verifyToken(ctx, platformPair[1], &platform); err != nil {
		return fmt.Errorf("platform token: %w", err)
	}
	if platform.Overall == nil || !*platform.Overall {
		return errors.New("overall attestation result is not true")
	}
	if !strings.EqualFold(platform.Nonce, hex.EncodeToString(nonce[:])) {
		return errors.New("nonce mismatch")
	}
	if err := n.checkTime(platform.Expiry, platform.NotBefore); err != nil {
		return err
	}
	if len(platform.Submods) != len(devices) {
		return errors.New("submods do not match the device tokens")
	}
	for name, token := range devices {
		var claims struct {
			Expiry    int64 `json:"exp"`
			NotBefore int64 `json:"nbf"`
		}
		if err := n.verifyToken(ctx, token, &claims); err != nil {
			return fmt.Errorf("%s token: %w", name, err)
		}
		if err := n.checkTime(claims.Expiry, claims.NotBefore); err != nil {
			return fmt.Errorf("%s token: %w", name, err)
		}
		var digest []any
		if err := json.Unmarshal(platform.Submods[name], &digest); err != nil || len(digest) != 2 || digest[0] != "DIGEST" {
			return fmt.Errorf("%s has no submod digest", name)
		}
		pair, ok := digest[1].([]any)
		if !ok || len(pair) != 2 || pair[0] != "SHA256" {
			return fmt.Errorf("%s submod digest is not SHA256", name)
		}
		sum := sha256.Sum256([]byte(token))
		if committed, _ := pair[1].(string); !strings.EqualFold(committed, hex.EncodeToString(sum[:])) {
			return fmt.Errorf("%s token is not the one the platform token commits", name)
		}
	}
	return nil
}

func (n *nras) checkTime(expiry, notBefore int64) error {
	now := n.now().Unix()
	if expiry == 0 || now >= expiry {
		return errors.New("token expired")
	}
	if notBefore != 0 && now < notBefore {
		return errors.New("token not yet valid")
	}
	return nil
}

// verifyToken checks an ES384 compact JWS and decodes its claims.
func (n *nras) verifyToken(ctx context.Context, token string, claims any) error {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return errors.New("not a compact JWS")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(segments[0], &header); err != nil {
		return err
	}
	if header.Alg != "ES384" {
		return fmt.Errorf("unexpected alg %q", header.Alg)
	}
	key, err := n.key(ctx, header.Kid)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil || len(signature) != 96 {
		return errors.New("malformed ES384 signature")
	}
	digest := sha512.Sum384([]byte(segments[0] + "." + segments[1]))
	r := new(big.Int).SetBytes(signature[:48])
	s := new(big.Int).SetBytes(signature[48:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return errors.New("bad signature")
	}
	return decodeSegment(segments[1], claims)
}

// key resolves kid against the NRAS JWKS, refetched on a miss because NVIDIA
// rotates its signing keys.
func (n *nras) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	n.mu.Lock()
	key, ok := n.keys[kid]
	n.mu.Unlock()
	if ok {
		return key, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, n.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := n.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("NRAS JWKS: %w", err)
	}
	defer response.Body.Close()
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("NRAS JWKS: %w", err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "EC" || jwk.Crv != "P-384" {
			continue
		}
		x, errX := base64.RawURLEncoding.DecodeString(jwk.X)
		y, errY := base64.RawURLEncoding.DecodeString(jwk.Y)
		if errX != nil || errY != nil || len(x) != 48 || len(y) != 48 {
			continue
		}
		public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), append(append([]byte{4}, x...), y...))
		if err != nil {
			continue
		}
		keys[jwk.Kid] = public
	}
	n.mu.Lock()
	n.keys = keys
	n.mu.Unlock()
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("unknown NRAS key %q", kid)
}

func decodeSegment(segment string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return errors.New("malformed JWS segment")
	}
	return json.Unmarshal(raw, out)
}
