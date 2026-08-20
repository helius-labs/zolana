package customring

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Properties:
// 1. Public: EdDSA input owners, default-ring output owners, and public asset transfers.
// 2. Private: custom-ring output owners, UTXO amounts, and UTXO assets.
// 3. The Solana runtime verifies EdDSA signatures; the circuit binds each real input owner to the public signer set.
// 4. Dummy slots are indistinguishable from real UTXO and address slots.
// 5. Input nullifiers are distinct and balances are preserved.

type CustomRingEddsaOnlyPublic struct {
	// Nullifiers for UTXO, address, and dummy input slots.
	Nullifiers []frontend.Variable
	// New output UTXO hashes.
	OutputHashes []frontend.Variable
	// UTXO tree roots to prove inclusion of real input UTXOs.
	UtxoTreeRoots []frontend.Variable
	// Nullifier tree roots to prove non-inclusion of input nullifiers.
	NullifierTreeRoots []frontend.Variable
	// Hash of input UTXO hashes, output UTXO hashes, address hashes, and external data.
	// Dummy UTXOs are represented as zero.
	PrivateTxHash frontend.Variable
	// Hash that ties arbitrary data to the proof.
	ExternalDataHash frontend.Variable
	// Assets in public asset transfers.
	PublicAssets [shared.NPublicSlots]frontend.Variable
	// Signed amounts in public asset transfers.
	PublicAmounts [shared.NPublicSlots]frontend.Variable
	// Program ID of the ring program.
	RingProgramID frontend.Variable
	// Whether dummy input UTXOs are allowed.
	// Dummy input UTXOs are not allowed once the nullifier tree capacity
	// is less than remaining state tree capacity to ensure that every new UTXO can be nullified.
	AllowDummyInputs frontend.Variable
	// Hashed EdDSA signer pubkeys, with the fee payer first.
	SignerPkHashes []frontend.Variable
	// Default-ring real outputs publish owner pubkey hashes; custom-ring real outputs
	// publish zero. Marked dummy outputs may publish a constrained participant.
	PublishedOutputOwnerPkHashes []frontend.Variable
	PublicInputHash              frontend.Variable `gnark:",public"`
}

type CustomRingEddsaOnlyPrivate struct {
	Inputs              []shared.Input
	InputOwnerPkHashes  []frontend.Variable
	Outputs             []shared.UtxoCircuitFields
	OutputOwnerPkHashes []frontend.Variable
	OutputNullifierPks  []frontend.Variable
	OutputBlindingSeed  frontend.Variable
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
		OutputBlindingSeed: c.Private.OutputBlindingSeed,
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
