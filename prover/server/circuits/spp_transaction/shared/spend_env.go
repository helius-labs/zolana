package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// P256SpendEnv builds the spend env for the P256 ownership rail: the witnessed
// owner pk_field and the shared signature over the P256 message digest.
func (c *Circuit) P256SpendEnv(api frontend.API) (SpendEnv, error) {
	ownerKeyHash, err := OwnerPkFieldFromPubkeyCircuit(api, c.P256Pub)
	if err != nil {
		return SpendEnv{}, err
	}
	p256Message, err := p256MessageHashToP256Fr(api, c.P256MessageHashLow, c.P256MessageHashHigh)
	if err != nil {
		return SpendEnv{}, err
	}
	return SpendEnv{
		P256PkField: ownerKeyHash,
		P256SigValid: c.P256Pub.IsValid(
			api,
			sw_emulated.GetCurveParams[emulated.P256Fp](),
			p256Message,
			&c.P256Sig,
		),
	}, nil
}

// EddsaOnlySpendEnv builds the spend env for the Solana-only rail: the P256
// message and signing key must be zero, and no P256-owned entry can validate.
func (c *Circuit) EddsaOnlySpendEnv(api frontend.API) SpendEnv {
	api.AssertIsEqual(c.P256MessageHashLow, 0)
	api.AssertIsEqual(c.P256MessageHashHigh, 0)
	api.AssertIsEqual(c.P256SigningPkField, 0)
	return SpendEnv{
		P256PkField:  frontend.Variable(0),
		P256SigValid: frontend.Variable(1),
		P256Sentinel: frontend.Variable(0),
	}
}
