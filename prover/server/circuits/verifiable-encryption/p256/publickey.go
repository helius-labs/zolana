package p256

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve"
)

type (
	PublicKey        = emcurve.PublicKey
	SelfKeyAgreement = emcurve.SelfKeyAgreement
)

// DerivePublicKey range-checks the big-endian secret key bytes, refuses a
// scalar that is zero modulo the group order and derives the public point.
func DerivePublicKey(api frontend.API, sk [32]frontend.Variable) PublicKey {
	return emcurve.DerivePublicKey(api, sk)
}

// SelfAgreeKey agrees a key between a public key and its own secret, reusing
// the point DerivePublicKey constrained instead of deriving it again.
func SelfAgreeKey(api frontend.API, key PublicKey) SelfKeyAgreement {
	return emcurve.SelfAgreeKey(api, key)
}
