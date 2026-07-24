package customzone

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

type CustomZoneAuthorityCircuit struct {
	shared.Circuit
}

func NewCustomZoneAuthorityCircuit(shape shared.Shape) (*CustomZoneAuthorityCircuit, error) {
	base, err := shared.NewCircuit(shape)
	if err != nil {
		return nil, err
	}
	return &CustomZoneAuthorityCircuit{Circuit: *base}, nil
}

func (c *CustomZoneAuthorityCircuit) Define(api frontend.API) error {
	if err := c.ValidateLayout(); err != nil {
		return err
	}

	env := c.EddsaOnlySpendEnv(api)

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		in := c.Inputs[i]
		shared.AssertWhen(api, in.IsReal(api), c.CheckZoneMember(api, in.Utxo))
		inputHashes[i], addressHashes[i] = shared.ConstrainEddsaOnlyInput(api, in, env)
	}
	c.AssertDistinctNullifiers(api)

	signers := c.SignerOwners(api)
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		out := c.Outputs[i]
		shared.AssertWhen(api, out.IsReal(api), c.CheckZoneMember(api, out.Utxo))
		outputHashes[i] = shared.ConstrainOutputShared(api, out, signers)
	}

	shared.AssertBalanceConservation(
		api,
		c.InputUtxos(),
		c.OutputUtxos(),
		c.PublicAssets[:],
		c.PublicAmounts[:],
	)

	api.AssertIsDifferent(c.ZoneProgramID, 0)

	privateTxHash := shared.PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, zoneAuthorityPublicInputHash(api, &c.Circuit))
	return nil
}

func zoneAuthorityPublicInputHash(api frontend.API, c *shared.Circuit) frontend.Variable {
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
	)
	return gadget.HashChain(api, fields)
}
