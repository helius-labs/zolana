package customring

import (
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

type CustomRingAuthorityExitPublic struct {
	Nullifiers                   []frontend.Variable
	OutputHashes                 []frontend.Variable
	TreeSlots                    []shared.TreeSlot
	OutputTreeID                 frontend.Variable
	PrivateTxHash                frontend.Variable
	ExternalDataHash             frontend.Variable
	PublicAssets                 [shared.NPublicSlots]frontend.Variable
	PublicAmounts                [shared.NPublicSlots]frontend.Variable
	RingProgramID                frontend.Variable
	SignerPkHashes               []frontend.Variable
	InputFlags                   frontend.Variable
	PublishedOutputOwnerPkHashes []frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type CustomRingAuthorityExitPrivate struct {
	Inputs              []shared.Input
	InputOwnerPkHashes  []frontend.Variable
	Outputs             []shared.UtxoCircuitFields
	OutputOwnerPkHashes []frontend.Variable
	OutputNullifierPks  []frontend.Variable
	BlindingSeed        frontend.Variable
}

// The ring authority rail with outputs that may leave the ring under a published owner tag.
type CustomRingAuthorityExitCircuit struct {
	CachedInputs shared.CachedInputs

	Shape   shared.Shape `gnark:"-"`
	Public  CustomRingAuthorityExitPublic
	Private CustomRingAuthorityExitPrivate
}

func NewCustomRingAuthorityExitCircuit(shape shared.Shape) (*CustomRingAuthorityExitCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomRingAuthorityExitCircuit{
		CachedInputs: shared.NewCachedInputs(shape.NInputs),
		Shape:        shape,
		Public: CustomRingAuthorityExitPublic{
			Nullifiers:                   make([]frontend.Variable, shape.NInputs),
			OutputHashes:                 make([]frontend.Variable, shape.NOutputs),
			TreeSlots:                    shared.NewTreeSlots(),
			SignerPkHashes:               make([]frontend.Variable, 1),
			PublishedOutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
		},
		Private: CustomRingAuthorityExitPrivate{
			Inputs:              shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes:  make([]frontend.Variable, shape.NInputs),
			Outputs:             make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
			OutputNullifierPks:  make([]frontend.Variable, shape.NOutputs),
		},
	}, nil
}

func (c *CustomRingAuthorityExitCircuit) transaction(api frontend.API) shared.Transaction {
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
		RingProgramID:     c.Public.RingProgramID,
		SignerPkHashChain: gadget.RightHashChain(api, c.Public.SignerPkHashes),
		InputFlags:        c.Public.InputFlags,
		PublicInputHash:   c.Public.PublicInputHash,
		PreimageTail: []frontend.Variable{
			gadget.RightHashChain4(api, c.Public.PublishedOutputOwnerPkHashes),
		},
	}
}

func (c *CustomRingAuthorityExitCircuit) Define(api frontend.API) error {
	tx := c.transaction(api)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: 1},
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Private.InputOwnerPkHashes), Want: c.Shape.NInputs},
		shared.LengthCheck{Name: "output owner pk hash", Got: len(c.Private.OutputOwnerPkHashes), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(c.Private.OutputNullifierPks), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "published output owner pk hash", Got: len(c.Public.PublishedOutputOwnerPkHashes), Want: c.Shape.NOutputs},
	); err != nil {
		return err
	}

	for _, input := range tx.Inputs {
		api.AssertIsDifferent(input.Utxo.Domain, shared.AddressDomain)
	}

	shared.AssertRingInputsFreeOutputs(api, tx.Inputs, tx.Outputs, c.Public.RingProgramID)
	api.AssertIsDifferent(c.Public.RingProgramID, 0)

	if err := shared.AssertOutputOwnerTags(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		c.Private.OutputNullifierPks,
	); err != nil {
		return err
	}
	if err := shared.AssertExitOwnersNamed(api, tx.Outputs, c.Private.OutputOwnerPkHashes); err != nil {
		return err
	}
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
		tx.OutputIsCompact,
		c.Public.PublishedOutputOwnerPkHashes,
		shared.Signers(c.Public.SignerPkHashes),
	); err != nil {
		return err
	}

	signers := shared.ConfidentialEddsaSigners(api, tx.Inputs, c.Private.InputOwnerPkHashes)
	signerOwners := shared.SignerOwners(api, tx.Inputs)
	return tx.Constrain(api, signers, signerOwners.ContainsEach(api, shared.OutputOwners(tx.Outputs)))
}
