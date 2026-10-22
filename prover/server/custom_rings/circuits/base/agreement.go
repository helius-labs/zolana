package base

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
)

// agreeCanonical is X25519(scalar, peer) for a peer encoded below p = 2^255-19, one encoding per key.
func agreeCanonical(api frontend.API, scalar, peer [32]frontend.Variable) [32]frontend.Variable {
	x25519.AssertCanonical(api, peer)
	return x25519.ECDH(api, scalar, peer)
}

// basepointByte is byte j of the X25519 base point u = 9.
func basepointByte(j int) frontend.Variable {
	if j == 0 {
		return 9
	}
	return 0
}
