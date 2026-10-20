package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

const CountersDisclosureDomain = "CRING/spend-counters/v1"

type successorCounters struct {
	salt   frontend.Variable
	assets [NVelocityAssets]frontend.Variable
	spent  [NVelocityAssets]frontend.Variable
}

func (s successorCounters) seal(api frontend.API, secret [32]frontend.Variable, salt [16]frontend.Variable) (frontend.Variable, error) {
	// 1. Derive the same tagged viewing key as the base proof. Its canonical
	// nonzero coordinate supplies a safe self-agreement peer.
	public := x25519.ScalarMulGenerator(api, secret)
	var compressed [33]frontend.Variable
	compressed[0] = 4
	copy(compressed[1:], public[:])
	// 2. The shared secret and key schedule mirror the host's counter seal.
	// This peer is derived from the secret, not supplied by an untrusted caller.
	dh := x25519.ECDH(api, secret, public)
	ikm := append(append(append([]frontend.Variable{}, dh[:]...), compressed[:]...), compressed[:]...)
	zeros := make([]frontend.Variable, 32)
	for i := range zeros {
		zeros[i] = 0
	}
	prk, err := counterHMAC(api, zeros, ikm)
	if err != nil {
		return nil, err
	}
	info := counterConstants([]byte("TSPP/hpke/TSPP/tx"))
	for _, b := range salt {
		api.ToBinary(b, 8)
	}
	info = append(info, salt[:]...)
	info = append(info, 255, 255, 255, 255)
	first, err := counterHMAC(api, prk, append(append([]frontend.Variable{}, info...), 1))
	if err != nil {
		return nil, err
	}
	second, err := counterHMAC(api, prk, append(append(append([]frontend.Variable{}, first...), info...), 2))
	if err != nil {
		return nil, err
	}
	var key [32]frontend.Variable
	var nonce [12]frontend.Variable
	copy(key[:], first)
	copy(nonce[:], second)

	// Canonical field bytes bind the encrypted opening to the record commitment.
	plaintext := counterFieldBytes(api, s.salt)
	for i, asset := range s.assets {
		plaintext = append(plaintext, counterFieldBytes(api, asset)...)
		bits := api.ToBinary(s.spent[i], 64)
		for j := 0; j < 8; j++ {
			plaintext = append(plaintext, api.FromBinary(bits[j*8:(j+1)*8]...))
		}
	}
	ciphertext := aes.NewCipher(api, key).CTREncrypt(nonce, plaintext)
	disclosure := counterConstants([]byte(CountersDisclosureDomain))
	disclosure = append(disclosure, salt[:]...)
	disclosure = append(disclosure, compressed[:]...)
	disclosure = append(disclosure, ciphertext...)
	return gadget.HashBytes(api, disclosure), nil
}

func counterFieldBytes(api frontend.API, value frontend.Variable) []frontend.Variable {
	bits := api.ToBinary(value)
	for len(bits) < 256 {
		bits = append(bits, 0)
	}
	out := make([]frontend.Variable, 32)
	for i := range out {
		out[31-i] = api.FromBinary(bits[i*8 : (i+1)*8]...)
	}
	return out
}

func counterConstants(bytes []byte) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = b
	}
	return out
}

func counterHMAC(api frontend.API, key, message []frontend.Variable) ([]frontend.Variable, error) {
	if len(key) != 32 {
		panic("invalid counter HMAC key length")
	}
	inner := make([]frontend.Variable, 64)
	outer := make([]frontend.Variable, 64)
	for i := range inner {
		if i < len(key) {
			inner[i] = counterXorPad(api, key[i], 0x36)
			outer[i] = counterXorPad(api, key[i], 0x5c)
		} else {
			inner[i], outer[i] = 0x36, 0x5c
		}
	}
	digest, err := counterSHA256(api, append(inner, message...))
	if err != nil {
		return nil, err
	}
	return counterSHA256(api, append(outer, digest...))
}

func counterSHA256(api frontend.API, input []frontend.Variable) ([]frontend.Variable, error) {
	h, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	bytes := make([]uints.U8, len(input))
	for i, b := range input {
		bytes[i] = uints.U8{Val: b}
	}
	h.Write(bytes)
	digest := h.Sum()
	out := make([]frontend.Variable, len(digest))
	for i, b := range digest {
		out[i] = b.Val
	}
	return out, nil
}

// HMAC pads are constants. Constrain each key byte before flipping its pad bits.
func counterXorPad(api frontend.API, value frontend.Variable, pad byte) frontend.Variable {
	bits := api.ToBinary(value, 8)
	for i := range bits {
		if pad&(1<<i) != 0 {
			bits[i] = api.Sub(1, bits[i])
		}
	}
	return api.FromBinary(bits...)
}
