package customzone

import (
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

type CustomZoneP256Circuit struct {
	shared.Circuit
}

func NewCustomZoneP256Circuit(shape shared.Shape) (*CustomZoneP256Circuit, error) {
	base, err := shared.NewCircuit(shape)
	if err != nil {
		return nil, err
	}
	return &CustomZoneP256Circuit{Circuit: *base}, nil
}

func (c *CustomZoneP256Circuit) Define(api frontend.API) error {
	if err := c.ValidateLayout(); err != nil {
		return err
	}

	env, err := c.P256SpendEnv(api)
	if err != nil {
		return err
	}
	env.P256Sentinel = frontend.Variable(0)

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		in := c.Inputs[i]
		shared.AssertWhen(api, in.IsReal(api), c.CheckZoneMemberOrFree(api, in.Utxo))
		inputHashes[i], addressHashes[i] = shared.ConstrainP256Input(api, in, env)
	}
	c.AssertDistinctNullifiers(api)

	signers := c.SignerOwners(api)
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		out := c.Outputs[i]
		shared.AssertWhen(api, out.IsReal(api), c.CheckZoneMemberOrFree(api, out.Utxo))
		outputHashes[i] = shared.ConstrainOutputShared(api, out, signers)
	}

	shared.AssertBalanceConservation(
		api,
		c.InputUtxos(),
		c.OutputUtxos(),
		c.PublicAssets[:],
		c.PublicAmounts[:],
	)

	privateTxHash := shared.PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, customZonePublicInputHash(api, &c.Circuit))
	return nil
}
