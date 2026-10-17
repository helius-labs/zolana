package base

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"

	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/x25519"
)

// AgreeAuditKey returns the tagged keys 0x04 || u and the DH of one clamped secret.
// The RFC gadget accepts recipient aliases, so a ring key must also be below p.
func AgreeAuditKey(api frontend.API, secret, recipient [32]frontend.Variable) (auditor, ephemeral [33]frontend.Variable, shared [32]frontend.Variable) {
	assertCanonicalX25519(api, recipient)
	shared = x25519.ECDH(api, secret, recipient)
	pub := x25519.ScalarMulGenerator(api, secret)
	auditor[0], ephemeral[0] = 4, 4
	copy(auditor[1:], recipient[:])
	copy(ephemeral[1:], pub[:])
	return
}

// assertCanonicalX25519 bounds every byte and rejects a u coordinate at or above p.
func assertCanonicalX25519(api frontend.API, key [32]frontend.Variable) {
	var bits []frontend.Variable
	var bound [256]frontend.Variable
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for _, b := range key {
		bits = append(bits, api.ToBinary(b, 8)...)
	}
	for i := range bound {
		bound[i] = p.Bit(i)
	}
	api.AssertIsEqual(cmp.IsLessBinary(api, bits, bound[:]), 1)
}
