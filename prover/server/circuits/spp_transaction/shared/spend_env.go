package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// P256SpendEnv builds the spend env for the P256 ownership rail: the witnessed
// owner pk_field and the shared signature over the P256 message digest carried
// as two big-endian 128-bit limbs.
func P256SpendEnv(api frontend.API, pub P256PublicKey, sig P256Signature, msgLow, msgHigh frontend.Variable) (SpendEnv, error) {
	ownerKeyHash, err := OwnerPkFieldFromPubkeyCircuit(api, pub)
	if err != nil {
		return SpendEnv{}, err
	}
	p256Message, err := p256MessageHashToP256Fr(api, msgLow, msgHigh)
	if err != nil {
		return SpendEnv{}, err
	}
	return SpendEnv{
		P256PkField: ownerKeyHash,
		P256SigValid: pub.IsValid(
			api,
			sw_emulated.GetCurveParams[emulated.P256Fp](),
			p256Message,
			&sig,
		),
	}, nil
}

// EddsaOnlySpendEnv is the sentinel env for the Solana-only rail: no P256
// witness exists on these variants, so no owner entry can ever route to the 0
// sentinel key (checkOwnershipEddsaOnly rejects isP256 outright).
func EddsaOnlySpendEnv() SpendEnv {
	return SpendEnv{
		P256PkField:  frontend.Variable(0),
		P256SigValid: frontend.Variable(1),
		P256Sentinel: frontend.Variable(0),
	}
}
