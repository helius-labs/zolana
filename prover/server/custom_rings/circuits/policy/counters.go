package policy

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/p256"
	ve "github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/aes"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

const CountersDisclosureDomain = "CRING/spend-counters/v1"

type successorCounters struct {
	salt   frontend.Variable
	assets [NVelocityAssets]frontend.Variable
	spent  [NVelocityAssets]frontend.Variable
}

// seal encrypts the counter opening to the viewing key with the SPP HPKE schedule, the caller checks the salt bytes.
func (s successorCounters) seal(api frontend.API, secret [32]frontend.Variable, salt [16]frontend.Variable) (frontend.Variable, error) {
	public := p256.ScalarMulGenerator(api, secret)
	compressed := p256.CompressPubkey(api, public)
	dh := p256.ECDH(api, secret, public)
	// A nil key is the all-zero HKDF salt.
	prk, err := counterHMAC(api, nil, slices.Concat(dh[:], compressed[:], compressed[:]))
	if err != nil {
		return nil, err
	}
	info := slices.Concat(base.ConstBytes("TSPP/hpke/TSPP/tx"), salt[:], []frontend.Variable{255, 255, 255, 255})
	first, err := counterHMAC(api, prk, slices.Concat(info, []frontend.Variable{1}))
	if err != nil {
		return nil, err
	}
	second, err := counterHMAC(api, prk, slices.Concat(first, info, []frontend.Variable{2}))
	if err != nil {
		return nil, err
	}
	// Canonical field bytes bind the opening to the record commitment, each counter is a little-endian u64.
	plaintext := ve.FieldToBytesBE(api, s.salt, 32)
	for i, asset := range s.assets {
		spent := ve.FieldToBytesBE(api, s.spent[i], 8)
		slices.Reverse(spent)
		plaintext = slices.Concat(plaintext, ve.FieldToBytesBE(api, asset, 32), spent)
	}
	ciphertext := aes.NewCipher(api, [32]frontend.Variable(first)).CTREncrypt([12]frontend.Variable(second[:12]), plaintext)
	return gadget.HashBytes(api, slices.Concat(base.ConstBytes(CountersDisclosureDomain), salt[:], compressed[:], ciphertext)), nil
}

func counterHMAC(api frontend.API, key, message []frontend.Variable) ([]frontend.Variable, error) {
	inner, outer := make([]frontend.Variable, 64), make([]frontend.Variable, 64)
	for i := range inner {
		inner[i], outer[i] = 0x36, 0x5c
		if i < len(key) {
			bits := api.ToBinary(key[i], 8)
			inner[i], outer[i] = xorPad(api, bits, 0x36), xorPad(api, bits, 0x5c)
		}
	}
	digest, err := counterSHA256(api, slices.Concat(inner, message))
	if err != nil {
		return nil, err
	}
	return counterSHA256(api, slices.Concat(outer, digest))
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

// xorPad flips the key bits where the constant pad is set.
func xorPad(api frontend.API, bits []frontend.Variable, pad byte) frontend.Variable {
	out := slices.Clone(bits)
	for i := range out {
		if pad>>i&1 == 1 {
			out[i] = api.Sub(1, out[i])
		}
	}
	return api.FromBinary(out...)
}
