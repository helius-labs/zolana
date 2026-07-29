package customzone

import (
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Properties:
// 1. Anonymity - public inputs do not reveal owners of UTXOs.
// 2. Dummy public inputs are indistinguishable from UTXO and address public inputs.
// 3. Solana program enforce the signature of the zone authority. The zone is free to implement its own signature.
// 4. All input and output UTXOs must be owned with the zone.
// 5. Nullifiers of UTXOs, dummies, addresses cannot collide.
// 6. Balances are preserved.

type CustomZoneAuthorityPublic struct {
	Nullifiers         []frontend.Variable
	OutputHashes       []frontend.Variable
	UtxoTreeRoots      []frontend.Variable
	NullifierTreeRoots []frontend.Variable
	PrivateTxHash      frontend.Variable
	ExternalDataHash   frontend.Variable
	PublicAssets       [shared.NPublicSlots]frontend.Variable
	PublicAmounts      [shared.NPublicSlots]frontend.Variable
	ZoneProgramID      frontend.Variable
	PayerPubkeyHash    frontend.Variable
	AllowDummyInputs   frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type CustomZoneAuthorityPrivate struct {
	Inputs             []shared.Input
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

func (c *CustomZoneAuthorityCircuit) transaction() shared.Transaction {
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
		AllowDummyInputs:   c.Public.AllowDummyInputs,
		PublicInputHash:    c.Public.PublicInputHash,
	}
}

func (c *CustomZoneAuthorityCircuit) Define(api frontend.API) error {
	tx := c.transaction()
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
