package base

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
)

// AgreeAuditKey returns the tagged keys 0x04 || u and the DH of one clamped secret.
// The RFC gadget accepts recipient aliases, so a ring key must also be below p.
func AgreeAuditKey(api frontend.API, secret, recipient [32]frontend.Variable) (auditor, ephemeral [33]frontend.Variable, shared [32]frontend.Variable) {
	x25519.AssertCanonical(api, recipient)
	shared = x25519.ECDH(api, secret, recipient)
	pub := x25519.ScalarMulGenerator(api, secret)
	auditor[0], ephemeral[0] = 4, 4
	copy(auditor[1:], recipient[:])
	copy(ephemeral[1:], pub[:])
	return
}

// assertCanonicalX25519Compact checks the byte encoding against 2^255-19.
// After bounding the top byte to 7 bits, only the maximal upper 247-bit
// prefix needs a low-byte comparison. All other prefixes are already below p.
func assertCanonicalX25519Compact(api frontend.API, key [32]frontend.Variable) {
	rc := rangecheck.New(api)
	for _, b := range key[:31] {
		rc.Check(b, 8)
	}
	rc.Check(key[31], 7)
	var high frontend.Variable = 0
	for i := 31; i >= 1; i-- {
		high = api.Add(api.Mul(high, 256), key[i])
	}
	maxHigh := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 247), big.NewInt(1))
	top := api.IsZero(api.Sub(high, maxHigh))
	rc.Check(api.Mul(top, api.Sub(236, key[0])), 8)
}
