package defaultring

import (
	"fmt"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Properties:
// 1. Public: EdDSA input and output owners, and public asset transfers.
// 2. Private: UTXO amounts and UTXO assets.
// 3. The circuit verifies NSigners Ed25519 signatures over the transaction digest and
//    publishes the chain of their owners' identities; those owners need not sign the
//    Solana transaction. The Solana runtime verifies the owner signers. Each real
//    input owner must be a verified owner or an owner signer.
// 4. All real input and output UTXOs belong to the default ring.
// 5. Dummy slots are indistinguishable from real UTXO and address slots.
// 6. Input nullifiers are distinct and balances are preserved.

type DefaultRingConfidentialInCircuitEddsaPublic struct {
	Nullifiers       []frontend.Variable
	OutputHashes     []frontend.Variable
	TreeSlots        []shared.TreeSlot
	OutputTreeID     frontend.Variable
	PrivateTxHash    frontend.Variable
	MessageHashLow   frontend.Variable
	MessageHashHigh  frontend.Variable
	ExternalDataHash frontend.Variable
	PublicAssets     [shared.NPublicSlots]frontend.Variable
	PublicAmounts    [shared.NPublicSlots]frontend.Variable
	InputFlags       frontend.Variable
	// Hashed EdDSA owner-signer pubkeys, deduplicated and zero-padded. The
	// in-circuit verified owner is not one; its identity is a public input of its own.
	SignerPkHashes []frontend.Variable
	// Owner pubkey hashes for all output slots. Real outputs publish their owners;
	// dummy outputs must name a transaction participant.
	OutputOwnerPkHashes []frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type DefaultRingConfidentialInCircuitEddsaPrivate struct {
	Inputs             []shared.Input
	InputOwnerPkHashes []frontend.Variable
	Outputs            []shared.UtxoCircuitFields
	OutputNullifierPks []frontend.Variable
	BlindingSeed       frontend.Variable
	OwnerPublicKeys    [][32]frontend.Variable
	OwnerSignatures    [][64]frontend.Variable
}

type DefaultRingConfidentialInCircuitEddsaCircuit struct {
	CachedInputs shared.CachedInputs

	Shape shared.Shape `gnark:"-"`
	// NSigners is the number of in-circuit verified owners; every key file
	// fixes it together with the shape.
	NSigners int `gnark:"-"`
	Public   DefaultRingConfidentialInCircuitEddsaPublic
	Private  DefaultRingConfidentialInCircuitEddsaPrivate
}

func NewDefaultRingConfidentialInCircuitEddsaCircuit(shape shared.Shape, nSigners int) (*DefaultRingConfidentialInCircuitEddsaCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	if nSigners < 1 {
		return nil, fmt.Errorf("spp: NSigners must be >= 1, got %d", nSigners)
	}
	return &DefaultRingConfidentialInCircuitEddsaCircuit{
		NSigners:     nSigners,
		CachedInputs: shared.NewCachedInputs(shape.NInputs),
		Shape:        shape,
		Public: DefaultRingConfidentialInCircuitEddsaPublic{
			Nullifiers:          make([]frontend.Variable, shape.NInputs),
			OutputHashes:        make([]frontend.Variable, shape.NOutputs),
			TreeSlots:           shared.NewTreeSlots(),
			SignerPkHashes:      make([]frontend.Variable, shape.SignerWidth()),
			OutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
		},
		Private: DefaultRingConfidentialInCircuitEddsaPrivate{
			Inputs:             shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes: make([]frontend.Variable, shape.NInputs),
			Outputs:            make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputNullifierPks: make([]frontend.Variable, shape.NOutputs),
			OwnerPublicKeys:    make([][32]frontend.Variable, nSigners),
			OwnerSignatures:    make([][64]frontend.Variable, nSigners),
		},
	}, nil
}

func (c *DefaultRingConfidentialInCircuitEddsaCircuit) newTransaction(
	api frontend.API,
	owners []frontend.Variable,
	messageHash frontend.Variable,
) shared.Transaction {
	return shared.Transaction{
		CachedInputs:      &c.CachedInputs,
		Shape:             c.Shape,
		Nullifiers:        c.Public.Nullifiers,
		OutputHashes:      c.Public.OutputHashes,
		OutputIsCompact:   shared.CompactSlots(api, c.Public.OutputHashes),
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
		// One field for any NSigners: SPP commits the same chain, which for a
		// single owner is that owner's identity.
		PreimageAfterPrivateTxHash: []frontend.Variable{
			messageHash,
			gadget.RightHashChain4(api, owners),
		},
		PreimageTail: []frontend.Variable{
			gadget.RightHashChain4(api, c.Public.OutputOwnerPkHashes),
		},
	}
}

func (c *DefaultRingConfidentialInCircuitEddsaCircuit) Define(api frontend.API) error {
	if err := shared.ValidateLength("owner public key", len(c.Private.OwnerPublicKeys), c.NSigners); err != nil {
		return err
	}
	if err := shared.ValidateLength("owner signature", len(c.Private.OwnerSignatures), c.NSigners); err != nil {
		return err
	}
	// Every owner signs the same transaction digest; each verification rebinds it.
	owners := make([]frontend.Variable, c.NSigners)
	var messageHash frontend.Variable
	for i := range owners {
		owners[i], messageHash = customring.OwnerAuthorization(
			api,
			c.Public.MessageHashLow,
			c.Public.MessageHashHigh,
			c.Private.OwnerPublicKeys[i],
			c.Private.OwnerSignatures[i],
		)
	}
	tx := c.newTransaction(api, owners, messageHash)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: c.Shape.SignerWidth()},
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Private.InputOwnerPkHashes), Want: c.Shape.NInputs},
		shared.LengthCheck{Name: "output owner pk hash", Got: len(c.Public.OutputOwnerPkHashes), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(c.Private.OutputNullifierPks), Want: c.Shape.NOutputs},
	); err != nil {
		return err
	}
	shared.AssertInDefaultRing(api, tx.Inputs, tx.Outputs)

	// ed25519.Verify asserts each signature, so its owner is authorized alongside
	// the owner signers.
	authorized := append(shared.Signers(nil), c.Public.SignerPkHashes...)
	authorized = append(authorized, owners...)
	inputOwners := shared.AuthorizedEddsaInputOwners(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		authorized,
	)
	if err := shared.AssertOutputOwnerTags(
		api,
		tx.Outputs,
		c.Public.OutputOwnerPkHashes,
		c.Private.OutputNullifierPks,
	); err != nil {
		return err
	}
	outputPubkeyIsSigner := authorized.ContainsEach(api, c.Public.OutputOwnerPkHashes)
	if err := shared.AssertDummyTags(
		api,
		tx.Inputs,
		tx.Outputs,
		tx.OutputIsCompact,
		nil,
		c.Public.OutputOwnerPkHashes,
		authorized,
	); err != nil {
		return err
	}

	return tx.Constrain(api, inputOwners, outputPubkeyIsSigner)
}
