package ringutils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// ViewingKeyLimbs binds all raw secret bytes, including RFC 7748 clamping bits.
// Each half is interpreted big-endian, matching the host commitment and KDF.
func ViewingKeyLimbs(api frontend.API, key [32]frontend.Variable) (lo, hi frontend.Variable) {
	for _, b := range key {
		bits.ToBinary(api, b, bits.WithNbDigits(8))
	}
	limbs := PackBytesBE(api, key[:], 16)
	return limbs[1], limbs[0]
}

func ViewingKeyCommitment(api frontend.API, key [32]frontend.Variable) frontend.Variable {
	lo, hi := ViewingKeyLimbs(api, key)
	return gadget.PoseidonHash(api, []frontend.Variable{lo, hi})
}

// TaggedPublicKey preserves the account encoding: 0x04 followed by the
// canonical little-endian X25519 Montgomery coordinate.
func TaggedPublicKey(api frontend.API, secret [32]frontend.Variable) [33]frontend.Variable {
	var tagged [33]frontend.Variable
	tagged[0] = 4
	u := x25519.ScalarMulGenerator(api, secret)
	copy(tagged[1:], u[:])
	return tagged
}

func PublicKeyCoordinate(api frontend.API, tagged [33]frontend.Variable) [32]frontend.Variable {
	api.AssertIsEqual(tagged[0], 4)
	var u [32]frontend.Variable
	copy(u[:], tagged[1:])
	x25519.AssertCanonical(api, u)
	return u
}
