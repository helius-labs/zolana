package transaction

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type DefaultZoneP256Circuit struct {
	Circuit
}

func NewDefaultZoneP256Circuit(shape Shape) (*DefaultZoneP256Circuit, error) {
	base, err := newCircuit(shape)
	if err != nil {
		return nil, err
	}
	return &DefaultZoneP256Circuit{Circuit: *base}, nil
}

func (c *DefaultZoneP256Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	env, err := c.p256SpendEnv(api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.P256SigningPkField, env.p256PkField)
	env.p256Sentinel = c.P256SigningPkField

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		in := c.Inputs[i]
		assertWhen(api, in.isReal(api), in.Utxo.checkNotInZone(api))
		inputHashes[i], addressHashes[i] = constrainP256Input(api, in, env)
	}
	c.assertDistinctNullifiers(api)

	signers := c.signerOwners(api)
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		outputHashes[i] = c.constrainDefaultZoneOutput(api, c.Outputs[i], signers)
	}

	assertBalanceConservation(
		api,
		c.inputUtxos(),
		c.outputUtxos(),
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
	)

	api.AssertIsEqual(c.ZoneProgramID, 0)

	privateTxHash := PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, c.defaultZonePublicInputHash(api))
	return nil
}

func (c *Circuit) p256SpendEnv(api frontend.API) (spendEnv, error) {
	ownerKeyHash, err := OwnerPkFieldFromPubkeyCircuit(api, c.P256Pub)
	if err != nil {
		return spendEnv{}, err
	}
	p256Message, err := p256MessageHashToP256Fr(api, c.P256MessageHashLow, c.P256MessageHashHigh)
	if err != nil {
		return spendEnv{}, err
	}
	return spendEnv{
		p256PkField: ownerKeyHash,
		p256SigValid: c.P256Pub.IsValid(
			api,
			sw_emulated.GetCurveParams[emulated.P256Fp](),
			p256Message,
			&c.P256Sig,
		),
	}, nil
}
