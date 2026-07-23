package transaction

import (
	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
)

type DefaultZoneEddsaOnlyCircuit struct {
	Circuit
}

func NewDefaultZoneEddsaOnlyCircuit(shape Shape) (*DefaultZoneEddsaOnlyCircuit, error) {
	base, err := newCircuit(shape, isEddsaOnly, isConfidential)
	if err != nil {
		return nil, err
	}
	return &DefaultZoneEddsaOnlyCircuit{Circuit: *base}, nil
}

func (c *DefaultZoneEddsaOnlyCircuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	env := c.eddsaOnlySpendEnv(api)

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		in := c.Inputs[i]
		assertWhen(api, in.isReal(api), in.Utxo.checkNotInZone(api))
		inputHashes[i], addressHashes[i] = constrainEddsaOnlyInput(api, in, env)
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

func (c *Circuit) eddsaOnlySpendEnv(api frontend.API) spendEnv {
	api.AssertIsEqual(c.P256MessageHashLow, 0)
	api.AssertIsEqual(c.P256MessageHashHigh, 0)
	api.AssertIsEqual(c.P256SigningPkField, 0)
	return spendEnv{
		p256PkField:  frontend.Variable(0),
		p256SigValid: frontend.Variable(1),
		p256Sentinel: frontend.Variable(0),
	}
}

func (c *Circuit) defaultZonePublicInputHash(api frontend.API) frontend.Variable {
	return gadget.HashChain(api, []frontend.Variable{
		gadget.HashChain(api, c.InputNullifiers()),
		gadget.HashChain(api, c.OutputHashes()),
		gadget.HashChain(api, c.InputUtxoRoots()),
		gadget.HashChain(api, c.InputNullifierTreeRoots()),
		c.PrivateTxHash,
		gadget.PoseidonHash(api, []frontend.Variable{c.P256MessageHashLow, c.P256MessageHashHigh}),
		c.ExternalDataHash,
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
		c.ZoneProgramID,
		c.PayerPubkeyHash,
		gadget.HashChain(api, c.InputOwnerPkHashes()),
		gadget.HashChain(api, c.OutputOwnerPkHashes()),
		c.P256SigningPkField,
	})
}
