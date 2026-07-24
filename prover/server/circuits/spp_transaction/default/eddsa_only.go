package defaultzone

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

type DefaultZoneEddsaOnlyCircuit struct {
	shared.Circuit
}

func NewDefaultZoneEddsaOnlyCircuit(shape shared.Shape) (*DefaultZoneEddsaOnlyCircuit, error) {
	base, err := shared.NewCircuit(shape)
	if err != nil {
		return nil, err
	}
	return &DefaultZoneEddsaOnlyCircuit{Circuit: *base}, nil
}

func (c *DefaultZoneEddsaOnlyCircuit) Define(api frontend.API) error {
	if err := c.ValidateLayout(); err != nil {
		return err
	}

	env := c.EddsaOnlySpendEnv(api)

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		in := c.Inputs[i]
		shared.AssertWhen(api, in.IsReal(api), in.Utxo.CheckNotInZone(api))
		inputHashes[i], addressHashes[i] = shared.ConstrainEddsaOnlyInput(api, in, env)
	}
	c.AssertDistinctNullifiers(api)

	signers := c.SignerOwners(api)
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		outputHashes[i] = c.ConstrainDefaultZoneOutput(api, c.Outputs[i], signers)
	}

	shared.AssertBalanceConservation(
		api,
		c.InputUtxos(),
		c.OutputUtxos(),
		c.PublicAssets[:],
		c.PublicAmounts[:],
	)

	api.AssertIsEqual(c.ZoneProgramID, 0)

	privateTxHash := shared.PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, defaultZonePublicInputHash(api, &c.Circuit))
	return nil
}

func defaultZonePublicInputHash(api frontend.API, c *shared.Circuit) frontend.Variable {
	fields := []frontend.Variable{
		gadget.HashChain(api, c.InputNullifiers()),
		gadget.HashChain(api, c.OutputHashes()),
		gadget.HashChain(api, c.InputUtxoRoots()),
		gadget.HashChain(api, c.InputNullifierTreeRoots()),
		c.PrivateTxHash,
		gadget.PoseidonHash(api, []frontend.Variable{c.P256MessageHashLow, c.P256MessageHashHigh}),
		c.ExternalDataHash,
	}
	fields = append(fields, c.PublicSlots()...)
	fields = append(fields,
		c.ZoneProgramID,
		c.PayerPubkeyHash,
		gadget.HashChain(api, c.InputOwnerPkHashes()),
		gadget.HashChain(api, c.OutputOwnerPkHashes()),
		c.P256SigningPkField,
	)
	return gadget.HashChain(api, fields)
}
