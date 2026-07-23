package transaction

import (
	"github.com/consensys/gnark/frontend"
)

type CustomZoneP256Circuit struct {
	Circuit
}

func NewCustomZoneP256Circuit(shape Shape) (*CustomZoneP256Circuit, error) {
	base, err := newCircuit(shape, isP256, isZone)
	if err != nil {
		return nil, err
	}
	return &CustomZoneP256Circuit{Circuit: *base}, nil
}

func (c *CustomZoneP256Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	env, err := c.p256SpendEnv(api)
	if err != nil {
		return err
	}
	env.p256Sentinel = frontend.Variable(0)

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		in := c.Inputs[i]
		assertWhen(api, in.isReal(api), c.checkZoneMemberOrFree(api, in.Utxo))
		inputHashes[i], addressHashes[i] = constrainP256Input(api, in, env)
	}
	c.assertDistinctNullifiers(api)

	signers := c.signerOwners(api)
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		out := c.Outputs[i]
		assertWhen(api, out.isReal(api), c.checkZoneMemberOrFree(api, out.Utxo))
		outputHashes[i] = constrainOutputShared(api, out, signers)
	}

	assertBalanceConservation(
		api,
		c.inputUtxos(),
		c.outputUtxos(),
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
	)

	privateTxHash := PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, c.customZonePublicInputHash(api))
	return nil
}
