package transaction

import (
	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
)

type CustomZoneAuthorityCircuit struct {
	Circuit
}

func NewCustomZoneAuthorityCircuit(shape Shape) (*CustomZoneAuthorityCircuit, error) {
	base, err := newCircuit(shape)
	if err != nil {
		return nil, err
	}
	return &CustomZoneAuthorityCircuit{Circuit: *base}, nil
}

func (c *CustomZoneAuthorityCircuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	env := c.eddsaOnlySpendEnv(api)

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		in := c.Inputs[i]
		assertWhen(api, in.isReal(api), c.checkZoneMember(api, in.Utxo))
		inputHashes[i], addressHashes[i] = constrainEddsaOnlyInput(api, in, env)
	}
	c.assertDistinctNullifiers(api)

	signers := c.signerOwners(api)
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		out := c.Outputs[i]
		assertWhen(api, out.isReal(api), c.checkZoneMember(api, out.Utxo))
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

	api.AssertIsDifferent(c.ZoneProgramID, 0)

	privateTxHash := PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, c.zoneAuthorityPublicInputHash(api))
	return nil
}

func (c *Circuit) zoneAuthorityPublicInputHash(api frontend.API) frontend.Variable {
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
	})
}
