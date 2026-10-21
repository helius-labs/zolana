package base

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
)

// agreeCanonical is X25519(scalar, peer) for a peer encoded below p = 2^255-19, one encoding per key.
func agreeCanonical(api frontend.API, scalar, peer [32]frontend.Variable) [32]frontend.Variable {
	// ECDH bounds every peer byte, the canonical check reads them as bytes.
	agreement := x25519.ECDH(api, scalar, peer)
	assertBelowP(api, peer)
	return agreement
}

// assertBelowP refuses a little-endian key at or above p or with bit 255 set, the caller bounds every byte.
func assertBelowP(api frontend.API, key [32]frontend.Variable) {
	rc := rangecheck.New(api)
	// 1. Bit 255 is clear, refusing the alias RFC 7748 masks away.
	rc.Check(key[31], 7)
	// 2. A key with the maximal 247-bit high part is below p only when its low byte is at most 236.
	var high frontend.Variable = 0
	for i := 31; i >= 1; i-- {
		high = api.Add(api.Mul(high, 256), key[i])
	}
	maxHigh := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 247), big.NewInt(1))
	top := api.IsZero(api.Sub(high, maxHigh))
	rc.Check(api.Mul(top, api.Sub(236, key[0])), 8)
}

// basepointByte is byte j of the X25519 base point u = 9.
func basepointByte(j int) frontend.Variable {
	if j == 0 {
		return 9
	}
	return 0
}
