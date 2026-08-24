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
	// Whether dummy input UTXOs are allowed.
	// Dummy input UTXOs are not allowed once the nullifier tree capacity
	// is less than remaining state tree capacity.
	AllowDummyInputs frontend.Variable
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
	PrivateTxBlinding  frontend.Variable
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
			UtxoTreeRoots:       make([]frontend.Variable, shape.NInputs),
			NullifierTreeRoots:  make([]frontend.Variable, shape.NInputs),
			SignerPkHashes:      make([]frontend.Variable, shape.NInputs+1),
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
		Shape:              c.Shape,
		Nullifiers:         c.Public.Nullifiers,
		OutputHashes:       c.Public.OutputHashes,
		UtxoTreeRoots:      c.Public.UtxoTreeRoots,
		NullifierTreeRoots: c.Public.NullifierTreeRoots,
		Inputs:             c.Private.Inputs,
		Outputs:            c.Private.Outputs,
		PrivateTxHash:      c.Public.PrivateTxHash,
		PrivateTxBlinding:  c.Private.PrivateTxBlinding,
		ExternalDataHash:   c.Public.ExternalDataHash,
		PublicAssets:       c.Public.PublicAssets,
		PublicAmounts:      c.Public.PublicAmounts,
		RingProgramID:      frontend.Variable(0),
		SignerPkHashChain:  gadget.RightHashChain(api, c.Public.SignerPkHashes),
		AllowDummyInputs:   c.Public.AllowDummyInputs,
		PublicInputHash:    c.Public.PublicInputHash,
		PreimageTail: []frontend.Variable{
			gadget.HashChain(api, c.Public.OutputOwnerPkHashes),
		},
	}
}

func (c *DefaultRingEddsaOnlyCircuit) Define(api frontend.API) error {
	tx := c.newTransaction(api)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: c.Shape.NInputs + 1},
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Private.InputOwnerPkHashes), Want: c.Shape.NInputs},
		shared.LengthCheck{Name: "output owner pk hash", Got: len(c.Public.OutputOwnerPkHashes), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(c.Private.OutputNullifierPks), Want: c.Shape.NOutputs},
	); err != nil {
		return err
	}
	// Assert that all input and output UTXOs are in the default ring.
	shared.AssertInDefaultRing(api, tx.Inputs, tx.Outputs)
	// Enforce confidentiality:
	// 1. Input utxos pubkeys are part of public inputs.
	// 2. Output UTXOs pubkeys are part of public input.
	// 3. All dummy UTXO tags must be a real transaction participant.
	if err := shared.AssertOutputOwnerTags(
		api,
		tx.Outputs,
		c.Public.OutputOwnerPkHashes,
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
	// An output containing program data must be owned by an authorized signer.
	outputPubkeyIsSigner := authorized.ContainsEach(api, c.Public.OutputOwnerPkHashes)
	// Every dummy tag must name a real input signer or real output owner.
	if err := shared.AssertDummyTags(
		api,
		tx.Inputs,
		tx.Outputs,
		nil,
		c.Public.OutputOwnerPkHashes,
		authorized,
	); err != nil {
		return err
	}

	return tx.Constrain(api, inputOwners, outputPubkeyIsSigner)
}
