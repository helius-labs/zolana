package tee

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type nrasFixture struct {
	key   *ecdsa.PrivateKey
	nras  *nras
	now   time.Time
	nonce [32]byte
}

func newNRASFixture(t *testing.T) *nrasFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "nv-test", "kty": "EC", "crv": "P-384",
			"x": base64.RawURLEncoding.EncodeToString(public[1:49]),
			"y": base64.RawURLEncoding.EncodeToString(public[49:]),
		}}})
	}))
	t.Cleanup(jwks.Close)
	f := &nrasFixture{key: key, now: time.Unix(1_800_000_000, 0)}
	f.nonce[0] = 9
	f.nras = newNRAS()
	f.nras.jwksURL = jwks.URL
	f.nras.now = func() time.Time { return f.now }
	return f
}

func (f *nrasFixture) sign(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "ES384", "kid": kid})
	claimsJSON, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha512.Sum384([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (f *nrasFixture) response(t *testing.T, edit func(platform map[string]any, device *string)) []byte {
	t.Helper()
	exp := f.now.Add(time.Hour).Unix()
	device := f.sign(t, "nv-test", map[string]any{"measres": "success", "exp": exp})
	platform := map[string]any{
		"x-nvidia-overall-att-result": true,
		"eat_nonce":                   hex.EncodeToString(f.nonce[:]),
		"exp":                         exp,
	}
	if edit != nil {
		edit(platform, &device)
	}
	sum := sha256.Sum256([]byte(device))
	if _, ok := platform["submods"]; !ok {
		platform["submods"] = map[string]any{"GPU-0": []any{"DIGEST", []any{"SHA256", hex.EncodeToString(sum[:])}}}
	}
	out, _ := json.Marshal([]any{[]string{"JWT", f.sign(t, "nv-test", platform)}, map[string]string{"GPU-0": device}})
	return out
}

func TestNRASVerify(t *testing.T) {
	f := newNRASFixture(t)
	if err := f.nras.verify(context.Background(), f.response(t, nil), f.nonce); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]any, *string){
		"overall false":  func(p map[string]any, _ *string) { p["x-nvidia-overall-att-result"] = false },
		"overall absent": func(p map[string]any, _ *string) { delete(p, "x-nvidia-overall-att-result") },
		"other nonce":    func(p map[string]any, _ *string) { p["eat_nonce"] = hex.EncodeToString(make([]byte, 32)) },
		"expired":        func(p map[string]any, _ *string) { p["exp"] = f.now.Unix() },
		"device swapped after commit": func(p map[string]any, d *string) {
			sum := sha256.Sum256([]byte(*d))
			p["submods"] = map[string]any{"GPU-0": []any{"DIGEST", []any{"SHA256", hex.EncodeToString(sum[:])}}}
			*d = f.sign(t, "nv-test", map[string]any{"measres": "fail", "exp": f.now.Add(time.Hour).Unix()})
		},
		"unknown key": func(_ map[string]any, d *string) {
			*d = f.sign(t, "nv-rotated-away", map[string]any{"exp": f.now.Add(time.Hour).Unix()})
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			if err := f.nras.verify(context.Background(), f.response(t, edit), f.nonce); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("bad signature", func(t *testing.T) {
		response := f.response(t, nil)
		var parts []json.RawMessage
		_ = json.Unmarshal(response, &parts)
		var platform []string
		_ = json.Unmarshal(parts[0], &platform)
		platform[1] = platform[1][:len(platform[1])-4] + "AAAA"
		tampered, _ := json.Marshal([]any{platform, parts[1]})
		if err := f.nras.verify(context.Background(), tampered, f.nonce); err == nil {
			t.Fatal("accepted")
		}
	})
}
