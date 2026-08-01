package customring

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Properties:
// 1. Anonymity - Input and output UTXO owner pubkeys are private inputs.
// 2. Dummy public inputs are indistinguishable from UTXO and address public inputs.
// 3. Solana program enforces eddsa signatures.
// 4. Nullifiers of UTXOs, dummies, addresses cannot collide.
// 5. Balances are preserved.

type CustomRingEddsaOnlyPublic struct {
	Nullifiers                   []frontend.Variable
	OutputHashes                 []frontend.Variable
	UtxoTreeRoots                []frontend.Variable
	NullifierTreeRoots           []frontend.Variable
	PrivateTxHash                frontend.Variable
	ExternalDataHash             frontend.Variable
	PublicAssets                 [shared.NPublicSlots]frontend.Variable
	PublicAmounts                [shared.NPublicSlots]frontend.Variable
	RingProgramID                frontend.Variable
	AllowDummyInputs             frontend.Variable
	SignerPkHashes               []frontend.Variable
	PublishedOutputOwnerPkHashes []frontend.Variable
	PublicInputHash              frontend.Variable `gnark:",public"`
}

type CustomRingEddsaOnlyPrivate struct {
	Inputs              []shared.Input
	InputOwnerPkHashes  []frontend.Variable
	Outputs             []shared.UtxoCircuitFields
	OutputOwnerPkHashes []frontend.Variable
	OutputNullifierPks  []frontend.Variable
}

type CustomRingEddsaOnlyCircuit struct {
	Shape   shared.Shape `gnark:"-"`
	Public  CustomRingEddsaOnlyPublic
	Private CustomRingEddsaOnlyPrivate
}

func NewCustomRingEddsaOnlyCircuit(shape shared.Shape) (*CustomRingEddsaOnlyCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomRingEddsaOnlyCircuit{
		Shape: shape,
		Public: CustomRingEddsaOnlyPublic{
			Nullifiers:                   make([]frontend.Variable, shape.NInputs),
			OutputHashes:                 make([]frontend.Variable, shape.NOutputs),
			UtxoTreeRoots:                make([]frontend.Variable, shape.NInputs),
			NullifierTreeRoots:           make([]frontend.Variable, shape.NInputs),
			SignerPkHashes:               make([]frontend.Variable, shape.NInputs+1),
			PublishedOutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
		},
		Private: CustomRingEddsaOnlyPrivate{
			Inputs:              shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes:  make([]frontend.Variable, shape.NInputs),
			Outputs:             make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
			OutputNullifierPks:  make([]frontend.Variable, shape.NOutputs),
		},
	}, nil
}

func (c *CustomRingEddsaOnlyCircuit) transaction(api frontend.API) shared.Transaction {
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
		RingProgramID:      c.Public.RingProgramID,
		SignerPkHashChain:  gadget.RightHashChain(api, c.Public.SignerPkHashes),
		AllowDummyInputs:   c.Public.AllowDummyInputs,
		PublicInputHash:    c.Public.PublicInputHash,
		PreimageTail: []frontend.Variable{
			gadget.HashChain(api, c.Public.PublishedOutputOwnerPkHashes),
		},
	}
}

func (c *CustomRingEddsaOnlyCircuit) Define(api frontend.API) error {
	tx := c.transaction(api)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: c.Shape.NInputs + 1},
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Private.InputOwnerPkHashes), Want: c.Shape.NInputs},
		shared.LengthCheck{Name: "output owner pk hash", Got: len(c.Private.OutputOwnerPkHashes), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(c.Private.OutputNullifierPks), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "published output owner pk hash", Got: len(c.Public.PublishedOutputOwnerPkHashes), Want: c.Shape.NOutputs},
	); err != nil {
		return err
	}

	shared.AssertRingMemberOrFree(api, tx.Inputs, tx.Outputs, c.Public.RingProgramID)
	api.AssertIsDifferent(c.Public.RingProgramID, 0)
	if err := shared.AssertOutputOwnerTags(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		c.Private.OutputNullifierPks,
	); err != nil {
		return err
	}

	authorized := shared.Signers(c.Public.SignerPkHashes)
	inputOwners := shared.AuthorizedEddsaInputOwners(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		authorized,
	)
	// If an output UTXO holds data the input must have signed a transaction.
	outputPubkeyIsSigner := authorized.ContainsEach(api, c.Private.OutputOwnerPkHashes)

	if err := shared.AssertPublishedOutputOwners(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		c.Public.PublishedOutputOwnerPkHashes,
	); err != nil {
		return err
	}
	if err := shared.AssertMaskedDummyOutputTags(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		c.Public.PublishedOutputOwnerPkHashes,
		authorized,
	); err != nil {
		return err
	}

	return tx.Constrain(api, inputOwners, outputPubkeyIsSigner)
}
