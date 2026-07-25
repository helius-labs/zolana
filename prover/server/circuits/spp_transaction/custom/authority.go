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

// transaction views this rail's witness as the shared transaction. Neither the
// input nor the output owner tags are published on this rail, so the preimage
// tail is empty; the message slot is the constant Poseidon(0, 0) the host feeds.
func (c *CustomZoneAuthorityCircuit) transaction(api frontend.API) shared.Transaction {
	return shared.Transaction{
		Shape:              c.Shape,
		Nullifiers:         c.Public.Nullifiers,
		OutputHashes:       c.Public.OutputHashes,
		UtxoTreeRoots:      c.Public.UtxoTreeRoots,
		NullifierTreeRoots: c.Public.NullifierTreeRoots,
		Inputs:             c.Private.Inputs,
		Outputs:            c.Private.Outputs,
		PrivateTxHash:      c.Public.PrivateTxHash,
		ExternalDataHash:   c.Public.ExternalDataHash,
		PublicAssets:       c.Public.PublicAssets,
		PublicAmounts:      c.Public.PublicAmounts,
		ZoneProgramID:      c.Public.ZoneProgramID,
		PayerPubkeyHash:    c.Public.PayerPubkeyHash,
		PublicInputHash:    c.Public.PublicInputHash,
		PreimageTail: []frontend.Variable{
			gadget.PoseidonHash(api, []frontend.Variable{0, 0}),
		},
	}
}

func (c *CustomZoneAuthorityCircuit) Define(api frontend.API) error {
	tx := c.transaction(api)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Private.InputOwnerPkHashes), Want: c.Shape.NInputs},
	); err != nil {
		return err
	}

	shared.AssertZoneMember(api, tx.Inputs, tx.Outputs, c.Public.ZoneProgramID)
	api.AssertIsDifferent(c.Public.ZoneProgramID, 0)

	signers := shared.EddsaOnlySigners(api, tx.Inputs, c.Private.InputOwnerPkHashes)
	signerOwners := shared.SignerOwners(api, tx.Inputs)
	return tx.Constrain(api, signers, signerOwners.ContainsEach(api, shared.OutputOwners(tx.Outputs)))
}
