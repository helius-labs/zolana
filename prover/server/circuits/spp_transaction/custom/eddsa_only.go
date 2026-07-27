package customzone

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Properties:
// 1. Confidentiality - Input and output UTXO owner pubkeys are public inputs.
// 2. Dummy public inputs are indistinguishable from UTXO and address public inputs.
// 3. Solana program enforces eddsa signatures.
// 4. Nullifiers of UTXOs, dummies, addresses cannot collide.
// 5. Balances are preserved.

type CustomZoneEddsaOnlyPublic struct {
	Nullifiers          []frontend.Variable
	OutputHashes        []frontend.Variable
	UtxoTreeRoots       []frontend.Variable
	NullifierTreeRoots  []frontend.Variable
	PrivateTxHash       frontend.Variable
	ExternalDataHash    frontend.Variable
	PublicAssets        [shared.NPublicSlots]frontend.Variable
	PublicAmounts       [shared.NPublicSlots]frontend.Variable
	ZoneProgramID       frontend.Variable
	PayerPubkeyHash     frontend.Variable
	AllowDummyInputs    frontend.Variable
	InputOwnerPkHashes  []frontend.Variable
	OutputOwnerPkHashes []frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type CustomZoneEddsaOnlyPrivate struct {
	Inputs             []shared.Input
	Outputs            []shared.UtxoCircuitFields
	OutputNullifierPks []frontend.Variable
}

type CustomZoneEddsaOnlyCircuit struct {
	Shape   shared.Shape `gnark:"-"`
	Public  CustomZoneEddsaOnlyPublic
	Private CustomZoneEddsaOnlyPrivate
}

func NewCustomZoneEddsaOnlyCircuit(shape shared.Shape) (*CustomZoneEddsaOnlyCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomZoneEddsaOnlyCircuit{
		Shape: shape,
		Public: CustomZoneEddsaOnlyPublic{
			Nullifiers:          make([]frontend.Variable, shape.NInputs),
			OutputHashes:        make([]frontend.Variable, shape.NOutputs),
			UtxoTreeRoots:       make([]frontend.Variable, shape.NInputs),
			NullifierTreeRoots:  make([]frontend.Variable, shape.NInputs),
			InputOwnerPkHashes:  make([]frontend.Variable, shape.NInputs),
			OutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
		},
		Private: CustomZoneEddsaOnlyPrivate{
			Inputs:             shared.NewInputs(shape.NInputs),
			Outputs:            make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputNullifierPks: make([]frontend.Variable, shape.NOutputs),
		},
	}, nil
}

func (c *CustomZoneEddsaOnlyCircuit) transaction(api frontend.API) shared.Transaction {
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
		PreimageTail: []frontend.Variable{
			gadget.HashChain(api, c.Public.InputOwnerPkHashes),
			gadget.HashChain(api, c.Public.OutputOwnerPkHashes),
		},
	}
}

func (c *CustomZoneEddsaOnlyCircuit) Define(api frontend.API) error {
	tx := c.transaction(api)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Public.InputOwnerPkHashes), Want: c.Shape.NInputs},
		shared.LengthCheck{Name: "output owner pk hash", Got: len(c.Public.OutputOwnerPkHashes), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(c.Private.OutputNullifierPks), Want: c.Shape.NOutputs},
	); err != nil {
		return err
	}

	shared.AssertZoneMemberOrFree(api, tx.Inputs, tx.Outputs, c.Public.ZoneProgramID)
	api.AssertIsDifferent(c.Public.ZoneProgramID, 0)
	if err := shared.AssertOutputOwnerTags(
		api,
		tx.Outputs,
		c.Public.OutputOwnerPkHashes,
		c.Private.OutputNullifierPks,
	); err != nil {
		return err
	}

	signers := shared.EddsaOnlySigners(api, tx.Inputs, c.Public.InputOwnerPkHashes)
	// If an output UTXO holds data the input must have signed a transaction.
	outputPubkeyIsSigner := signers.ContainsEach(api, c.Public.OutputOwnerPkHashes)

	// Every published dummy tag must identify a signer or the fee payer.
	if err := shared.AssertDummyTags(
		api,
		tx.Inputs,
		tx.Outputs,
		c.Public.InputOwnerPkHashes,
		c.Public.OutputOwnerPkHashes,
		signers,
		c.Public.PayerPubkeyHash,
	); err != nil {
		return err
	}

	return tx.Constrain(api, signers, outputPubkeyIsSigner)
}
