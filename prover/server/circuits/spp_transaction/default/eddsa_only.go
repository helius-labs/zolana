package defaultring

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Properties:
// 1. Public: EdDSA input and output owners, and public asset transfers.
// 2. Private: UTXO amounts and UTXO assets.
// 3. The Solana runtime verifies EdDSA signatures; the circuit binds each real input owner to the public signer set.
// 4. All real input and output UTXOs belong to the default ring.
// 5. Dummy slots are indistinguishable from real UTXO and address slots.
// 6. Input nullifiers are distinct and balances are preserved.

type DefaultRingEddsaOnlyPublic struct {
	// Nullifiers for UTXO, address, and dummy input slots.
	Nullifiers []frontend.Variable
	// New output UTXO hashes.
	OutputHashes []frontend.Variable
	// Input tree slots: each tree's raw u16 id and both roots, selected as a
	// unit by every input's private tree slot.
	TreeSlots []shared.TreeSlot
	// Raw u16 id of the output tree.
	OutputTreeID frontend.Variable
	// Hash of input UTXO hashes, output UTXO hashes, address hashes, and external data.
	// Dummy UTXOs are represented as zero.
	PrivateTxHash frontend.Variable
	// Hash that ties arbitrary data to the proof.
	ExternalDataHash frontend.Variable
	// Assets in public asset transfers.
	PublicAssets [shared.NPublicSlots]frontend.Variable
	// Signed amounts in public asset transfers.
	PublicAmounts [shared.NPublicSlots]frontend.Variable
	// Packed input flags: bit 0 says whether dummy input UTXOs are allowed, and
	// input i's tree index occupies the shared.TreeIndexBits bits starting at
	// 1+shared.TreeIndexBits*i. Dummy input UTXOs are not allowed once the
	// nullifier tree capacity is less than remaining state tree capacity.
	InputFlags frontend.Variable
	// Hashed EdDSA signer pubkeys, with the fee payer first.
	SignerPkHashes []frontend.Variable
	// Owner pubkey hashes for all output slots. Real outputs publish their owners;
	// dummy outputs must name a transaction participant.
	OutputOwnerPkHashes []frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type DefaultRingEddsaOnlyPrivate struct {
	Inputs             []shared.Input
	InputOwnerPkHashes []frontend.Variable
	Outputs            []shared.UtxoCircuitFields
	OutputNullifierPks []frontend.Variable
	// Private random seed for deriving output UTXO and transaction hash blindings.
	BlindingSeed frontend.Variable
}

type DefaultRingEddsaOnlyCircuit struct {
	Shape   shared.Shape `gnark:"-"`
	Public  DefaultRingEddsaOnlyPublic
	Private DefaultRingEddsaOnlyPrivate
}

func NewDefaultRingEddsaOnlyCircuit(shape shared.Shape) (*DefaultRingEddsaOnlyCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &DefaultRingEddsaOnlyCircuit{
		Shape: shape,
		Public: DefaultRingEddsaOnlyPublic{
			Nullifiers:          make([]frontend.Variable, shape.NInputs),
			OutputHashes:        make([]frontend.Variable, shape.NOutputs),
			TreeSlots:           shared.NewTreeSlots(),
			SignerPkHashes:      make([]frontend.Variable, shape.SignerWidth()),
			OutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
		},
		Private: DefaultRingEddsaOnlyPrivate{
			Inputs:             shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes: make([]frontend.Variable, shape.NInputs),
			Outputs:            make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputNullifierPks: make([]frontend.Variable, shape.NOutputs),
		},
	}, nil
}

func (c *DefaultRingEddsaOnlyCircuit) newTransaction(api frontend.API) shared.Transaction {
	return shared.Transaction{
		Shape:             c.Shape,
		Nullifiers:        c.Public.Nullifiers,
		OutputHashes:      c.Public.OutputHashes,
		TreeSlots:         c.Public.TreeSlots,
		OutputTreeID:      c.Public.OutputTreeID,
		Inputs:            c.Private.Inputs,
		Outputs:           c.Private.Outputs,
		BlindingSeed:      c.Private.BlindingSeed,
		PrivateTxHash:     c.Public.PrivateTxHash,
		ExternalDataHash:  c.Public.ExternalDataHash,
		PublicAssets:      c.Public.PublicAssets,
		PublicAmounts:     c.Public.PublicAmounts,
		RingProgramID:     frontend.Variable(0),
		SignerPkHashChain: gadget.RightHashChain(api, c.Public.SignerPkHashes),
		InputFlags:        c.Public.InputFlags,
		PublicInputHash:   c.Public.PublicInputHash,
		PreimageTail: []frontend.Variable{
			gadget.HashChain4(api, c.Public.OutputOwnerPkHashes),
		},
	}
}

func (c *DefaultRingEddsaOnlyCircuit) Define(api frontend.API) error {
	tx := c.newTransaction(api)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: c.Shape.SignerWidth()},
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Private.InputOwnerPkHashes), Want: c.Shape.NInputs},
		shared.LengthCheck{Name: "output owner pk hash", Got: len(c.Public.OutputOwnerPkHashes), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(c.Private.OutputNullifierPks), Want: c.Shape.NOutputs},
	); err != nil {
		return err
	}
	// Assert that all input and output UTXOs are in the default ring.
	shared.AssertInDefaultRing(api, tx.Inputs, tx.Outputs)
	// Enforce confidentiality:
	// 1. Input owners are private and each must be in the public signer vector.
	// 2. Output UTXOs pubkeys are part of public input.
	// 3. Every dummy tag names an owner signer other than the payer or a real
	//    output owner.

	// 1.
	authorized := shared.Signers(c.Public.SignerPkHashes)
	inputOwners := shared.AuthorizedEddsaInputOwners(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		authorized,
	)
	// 2.
	if err := shared.AssertOutputOwnerTags(
		api,
		tx.Outputs,
		c.Public.OutputOwnerPkHashes,
		c.Private.OutputNullifierPks,
	); err != nil {
		return err
	}

	// An output containing program data must be owned by an authorized signer.
	outputPubkeyIsSigner := authorized.ContainsEach(api, c.Public.OutputOwnerPkHashes)
	// 3.
	if err := shared.AssertDummyTags(
		api,
		tx.Inputs,
		tx.Outputs,
		nil,
		c.Public.OutputOwnerPkHashes,
		authorized.WithoutPayer(),
	); err != nil {
		return err
	}

	return tx.Constrain(api, inputOwners, outputPubkeyIsSigner)
}
