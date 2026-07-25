package customzone

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// CustomZoneAuthorityPublic is the zone-authority rail's public-input-hash
// preimage: the zone authority controls its zone-owned UTXOs, so no owner pk
// hash is published (input owner tags stay private) and no P256 witness
// exists; the p256_message_hash preimage slot is the constant the host feeds
// (Poseidon(0, 0)), baked into publicInputHash.
type CustomZoneAuthorityPublic struct {
	Nullifiers         []frontend.Variable
	OutputHashes       []frontend.Variable
	UtxoTreeRoots      []frontend.Variable
	NullifierTreeRoots []frontend.Variable
	PrivateTxHash      frontend.Variable
	ExternalDataHash   frontend.Variable
	// PublicAssets/PublicAmounts are the uniform public movement slots: a
	// signed net flow per asset (SOL is an ordinary asset id). Idle slots are
	// pinned to (0, 0) by AssertBalanceConservation.
	PublicAssets    [shared.NPublicSlots]frontend.Variable
	PublicAmounts   [shared.NPublicSlots]frontend.Variable
	ZoneProgramID   frontend.Variable
	PayerPubkeyHash frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type CustomZoneAuthorityPrivate struct {
	Inputs []shared.Input
	// InputOwnerPkHashes stay private on this rail: they still drive the
	// ownership check but are omitted from the public input hash.
	InputOwnerPkHashes []frontend.Variable
	Outputs            []shared.UtxoCircuitFields
}

type CustomZoneAuthorityCircuit struct {
	Shape   shared.Shape `gnark:"-"`
	Public  CustomZoneAuthorityPublic
	Private CustomZoneAuthorityPrivate
}

func NewCustomZoneAuthorityCircuit(shape shared.Shape) (*CustomZoneAuthorityCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomZoneAuthorityCircuit{
		Shape: shape,
		Public: CustomZoneAuthorityPublic{
			Nullifiers:         make([]frontend.Variable, shape.NInputs),
			OutputHashes:       make([]frontend.Variable, shape.NOutputs),
			UtxoTreeRoots:      make([]frontend.Variable, shape.NInputs),
			NullifierTreeRoots: make([]frontend.Variable, shape.NInputs),
		},
		Private: CustomZoneAuthorityPrivate{
			Inputs:             shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes: make([]frontend.Variable, shape.NInputs),
			Outputs:            make([]shared.UtxoCircuitFields, shape.NOutputs),
		},
	}, nil
}

func (c *CustomZoneAuthorityCircuit) validateLayout() error {
	if err := shared.ValidateInputs(c.Shape.NInputs, c.Private.Inputs); err != nil {
		return err
	}
	checks := []struct {
		name      string
		got, want int
	}{
		{"nullifier", len(c.Public.Nullifiers), c.Shape.NInputs},
		{"output hash", len(c.Public.OutputHashes), c.Shape.NOutputs},
		{"utxo tree root", len(c.Public.UtxoTreeRoots), c.Shape.NInputs},
		{"nullifier tree root", len(c.Public.NullifierTreeRoots), c.Shape.NInputs},
		{"input owner pk hash", len(c.Private.InputOwnerPkHashes), c.Shape.NInputs},
		{"output", len(c.Private.Outputs), c.Shape.NOutputs},
	}
	for _, check := range checks {
		if err := shared.ValidateLength(check.name, check.got, check.want); err != nil {
			return err
		}
	}
	return nil
}

func (c *CustomZoneAuthorityCircuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	signers := shared.EddsaOnlySigners(api, c.Private.Inputs, c.Private.InputOwnerPkHashes)

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i, in := range c.Private.Inputs {
		shared.AssertWhen(api, in.IsUtxo(api), shared.CheckZoneMember(api, in.Utxo, c.Public.ZoneProgramID))
		signals := shared.InputSignals{
			Nullifier:         c.Public.Nullifiers[i],
			UtxoTreeRoot:      c.Public.UtxoTreeRoots[i],
			NullifierTreeRoot: c.Public.NullifierTreeRoots[i],
			SignerPk:          signers[i],
		}
		inputHashes[i], addressHashes[i] = shared.ConstrainInput(api, in, signals)
	}
	shared.AssertDistinctNullifiers(api, c.Public.Nullifiers)

	signerOwners := shared.SignerOwners(api, c.Private.Inputs)
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i, utxo := range c.Private.Outputs {
		shared.AssertWhen(api, utxo.IsUtxo(api), shared.CheckZoneMember(api, utxo, c.Public.ZoneProgramID))
		outputHashes[i] = shared.ConstrainCustomZoneOutput(api, utxo, c.Public.OutputHashes[i], signerOwners)
	}

	shared.AssertBalanceConservation(
		api,
		shared.InputUtxos(c.Private.Inputs),
		c.Private.Outputs,
		c.Public.PublicAssets[:],
		c.Public.PublicAmounts[:],
	)

	api.AssertIsDifferent(c.Public.ZoneProgramID, 0)

	privateTxHash := shared.PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		c.Public.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)

	api.AssertIsEqual(c.Public.PublicInputHash, c.publicInputHash(api))
	return nil
}

func (c *CustomZoneAuthorityCircuit) publicInputHash(api frontend.API) frontend.Variable {
	fields := []frontend.Variable{
		gadget.HashChain(api, c.Public.Nullifiers),
		gadget.HashChain(api, c.Public.OutputHashes),
		gadget.HashChain(api, c.Public.UtxoTreeRoots),
		gadget.HashChain(api, c.Public.NullifierTreeRoots),
		c.Public.PrivateTxHash,
		// No P256 message on this rail: the host feeds the zero-limb digest.
		gadget.PoseidonHash(api, []frontend.Variable{0, 0}),
		c.Public.ExternalDataHash,
	}
	fields = append(fields, shared.PublicSlots(c.Public.PublicAssets, c.Public.PublicAmounts)...)
	fields = append(fields,
		c.Public.ZoneProgramID,
		c.Public.PayerPubkeyHash,
	)
	return gadget.HashChain(api, fields)
}
