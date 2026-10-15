package customring

import (
	"github.com/helius-labs/zolana/prover/server/circuits/ed25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	checked "github.com/helius-labs/zolana/prover/server/circuits/gadget/v2"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// The anonymous ring rail. A zero input owner tag selects the hidden Ed25519
// owner, whose signature over the RingP256 message digest is verified in circuit.

type CustomRingEd25519Public struct {
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
	RingProgramID    frontend.Variable
	InputFlags       frontend.Variable
	SignerPkHashes   []frontend.Variable
	PublicInputHash  frontend.Variable `gnark:",public"`
}

type CustomRingEd25519Private struct {
	Inputs              []shared.Input
	InputOwnerPkHashes  []frontend.Variable
	Outputs             []shared.UtxoCircuitFields
	OutputOwnerPkHashes []frontend.Variable
	OutputNullifierPks  []frontend.Variable
	BlindingSeed        frontend.Variable
	OwnerPublicKey      [32]frontend.Variable
	OwnerSignature      [64]frontend.Variable
}

type CustomRingEd25519Circuit struct {
	CachedInputs shared.CachedInputs

	Shape   shared.Shape `gnark:"-"`
	Public  CustomRingEd25519Public
	Private CustomRingEd25519Private
}

func NewCustomRingEd25519Circuit(shape shared.Shape) (*CustomRingEd25519Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomRingEd25519Circuit{
		CachedInputs: shared.NewCachedInputs(shape.NInputs),
		Shape:        shape,
		Public: CustomRingEd25519Public{
			Nullifiers:     make([]frontend.Variable, shape.NInputs),
			OutputHashes:   make([]frontend.Variable, shape.NOutputs),
			TreeSlots:      shared.NewTreeSlots(),
			SignerPkHashes: make([]frontend.Variable, shape.SignerWidth()),
		},
		Private: CustomRingEd25519Private{
			Inputs:              shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes:  make([]frontend.Variable, shape.NInputs),
			Outputs:             make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
			OutputNullifierPks:  make([]frontend.Variable, shape.NOutputs),
		},
	}, nil
}

// transaction commits the RingP256 preimage with a zero default owner and zero
// published output owners, so the program assembles both rails alike.
func (c *CustomRingEd25519Circuit) transaction(
	api frontend.API,
	messageHash frontend.Variable,
	publishedOutputOwners []frontend.Variable,
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
		RingProgramID:     c.Public.RingProgramID,
		SignerPkHashChain: gadget.RightHashChain(api, c.Public.SignerPkHashes),
		InputFlags:        c.Public.InputFlags,
		PublicInputHash:   c.Public.PublicInputHash,
		PreimageAfterPrivateTxHash: []frontend.Variable{
			messageHash,
			0,
		},
		PreimageTail: []frontend.Variable{
			gadget.RightHashChain4(api, publishedOutputOwners),
		},
	}
}

func (c *CustomRingEd25519Circuit) Define(api frontend.API) error {
	messageBits := append(
		api.ToBinary(c.Public.MessageHashLow, p256MessageLimbBits),
		api.ToBinary(c.Public.MessageHashHigh, p256MessageLimbBits)...,
	)
	message := bytes32FromBits(api, messageBits)
	key := ed25519.Verify(api, ed25519.Inputs{
		PublicKey: c.Private.OwnerPublicKey,
		Signature: c.Private.OwnerSignature,
		Message:   message[:],
	})
	hiddenOwner := checked.SolanaOwnerIdentity(api, key)

	publishedOutputOwners := make([]frontend.Variable, c.Shape.NOutputs)
	for i := range publishedOutputOwners {
		publishedOutputOwners[i] = 0
	}
	tx := c.transaction(api, gadget.HashBytes(api, message[:]), publishedOutputOwners)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: c.Shape.SignerWidth()},
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Private.InputOwnerPkHashes), Want: c.Shape.NInputs},
		shared.LengthCheck{Name: "output owner pk hash", Got: len(c.Private.OutputOwnerPkHashes), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(c.Private.OutputNullifierPks), Want: c.Shape.NOutputs},
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

	authorizedEddsa := shared.Signers(c.Public.SignerPkHashes)
	// The zero-tag resolver is algorithm independent, and ed25519.Verify already asserts the signature.
	inputOwners := shared.P256Signers(api, tx.Inputs, c.Private.InputOwnerPkHashes, authorizedEddsa, hiddenOwner, 1)
	shared.AssertHiddenRingOwner(api, tx.Inputs, c.Private.InputOwnerPkHashes, authorizedEddsa, hiddenOwner)
	// A cache read publishes the commitment of the note it spends.
	api.AssertIsEqual(c.CachedInputs.TreeID, 0)
	for i := range c.CachedInputs.IsCached {
		api.AssertIsEqual(c.CachedInputs.IsCached[i], 0)
		api.AssertIsEqual(c.CachedInputs.ReadHashes[i], 0)
	}

	authorized := append(shared.Signers(nil), authorizedEddsa...)
	authorized = append(authorized, hiddenOwner)
	outputPubkeyIsSigner := authorized.ContainsEach(api, c.Private.OutputOwnerPkHashes)
	if err := shared.AssertPublishedOutputOwners(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		publishedOutputOwners,
	); err != nil {
		return err
	}

	return tx.Constrain(api, inputOwners, outputPubkeyIsSigner)
}
