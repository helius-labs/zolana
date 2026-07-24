package defaultzone

import (
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

type DefaultZoneP256Circuit struct {
	shared.Circuit
}

func NewDefaultZoneP256Circuit(shape shared.Shape) (*DefaultZoneP256Circuit, error) {
	base, err := shared.NewCircuit(shape)
	if err != nil {
		return nil, err
	}
	return &DefaultZoneP256Circuit{Circuit: *base}, nil
}

func (c *DefaultZoneP256Circuit) Define(api frontend.API) error {
	if err := c.ValidateLayout(); err != nil {
		return err
	}

	env, err := c.P256SpendEnv(api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.P256SigningPkField, env.P256PkField)
	env.P256Sentinel = c.P256SigningPkField

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		in := c.Inputs[i]
		shared.AssertWhen(api, in.IsReal(api), in.Utxo.CheckNotInZone(api))
		inputHashes[i], addressHashes[i] = shared.ConstrainP256Input(api, in, env)
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
