package customring

import (
	"github.com/helius-labs/zolana/prover/server/circuits/ed25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	checked "github.com/helius-labs/zolana/prover/server/circuits/gadget/v2"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// The anonymous ring rail. A zero input owner tag selects the hidden Ed25519
// owner, whose signature over the shared ring-spend digest is verified in circuit.
// Every real output stays in the signing ring. The rail publishes zero output
// owners, and a default-ring output would have to publish its owner, so the
// only one provable under zero would be the unspendable zero identity.

type CustomRingAnonymousEd25519Public struct {
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

type CustomRingAnonymousEd25519Private struct {
	Inputs              []shared.Input
	InputOwnerPkHashes  []frontend.Variable
	Outputs             []shared.UtxoCircuitFields
	OutputOwnerPkHashes []frontend.Variable
	OutputNullifierPks  []frontend.Variable
	BlindingSeed        frontend.Variable
	OwnerPublicKey      [32]frontend.Variable
	OwnerSignature      [64]frontend.Variable
}

type CustomRingAnonymousEd25519Circuit struct {
	CachedInputs shared.CachedInputs

	Shape   shared.Shape `gnark:"-"`
	Public  CustomRingAnonymousEd25519Public
	Private CustomRingAnonymousEd25519Private
}

// NewCustomRingAnonymousEd25519Circuit allocates only a supported transaction shape.
func NewCustomRingAnonymousEd25519Circuit(shape shared.Shape) (*CustomRingAnonymousEd25519Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomRingAnonymousEd25519Circuit{
		CachedInputs: shared.NewCachedInputs(shape.NInputs),
		Shape:        shape,
		Public: CustomRingAnonymousEd25519Public{
			Nullifiers:     make([]frontend.Variable, shape.NInputs),
			OutputHashes:   make([]frontend.Variable, shape.NOutputs),
			TreeSlots:      shared.NewTreeSlots(),
			SignerPkHashes: make([]frontend.Variable, shape.SignerWidth()),
		},
		Private: CustomRingAnonymousEd25519Private{
			Inputs:              shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes:  make([]frontend.Variable, shape.NInputs),
			Outputs:             make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
			OutputNullifierPks:  make([]frontend.Variable, shape.NOutputs),
		},
	}, nil
}

// transaction commits the signed ring preimage with a zero default owner and
// zero published output owners to preserve the anonymous statement.
func (c *CustomRingAnonymousEd25519Circuit) transaction(
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

// Define authenticates a private Ed25519 owner and binds its spends to the
// existing ring transaction statement without publishing that owner.
func (c *CustomRingAnonymousEd25519Circuit) Define(api frontend.API) error {
	// 1. Verify the exact public spend digest under the hidden owner key.
	messageBits := append(
		api.ToBinary(c.Public.MessageHashLow, messageLimbBits),
		api.ToBinary(c.Public.MessageHashHigh, messageLimbBits)...,
	)
	message := checked.BitsToBytesBE(api, messageBits)
	key := ed25519.Verify(api, ed25519.Inputs{
		PublicKey: c.Private.OwnerPublicKey,
		Signature: c.Private.OwnerSignature,
		Message:   message,
	})
	hiddenOwner := checked.SolanaOwnerIdentity(api, key)

	// 2. Reuse the ring transaction preimage with every output owner hidden.
	// An output carrying the confidential encrypted scheme bundle cannot verify
	// under this rail. The program hashes its owner tag where the circuit commits zero.
	publishedOutputOwners := make([]frontend.Variable, c.Shape.NOutputs)
	for i := range publishedOutputOwners {
		publishedOutputOwners[i] = 0
	}
	tx := c.transaction(api, gadget.HashBytes(api, message), publishedOutputOwners)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: c.Shape.SignerWidth()},
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Private.InputOwnerPkHashes), Want: c.Shape.NInputs},
		shared.LengthCheck{Name: "output owner pk hash", Got: len(c.Private.OutputOwnerPkHashes), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(c.Private.OutputNullifierPks), Want: c.Shape.NOutputs},
	); err != nil {
		return err
	}

	// 3. Restrict membership and bind each private output owner opening.
	// Inputs may leave the default ring, real outputs may not enter it.
	shared.AssertRingMemberOrFree(api, tx.Inputs, nil, c.Public.RingProgramID)
	shared.AssertRingMember(api, nil, tx.Outputs, c.Public.RingProgramID)
	api.AssertIsDifferent(c.Public.RingProgramID, 0)
	if err := shared.AssertOutputOwnerTags(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		c.Private.OutputNullifierPks,
	); err != nil {
		return err
	}

	// 4. Authorize input owners and prevent address or cache metadata leaks.
	authorizedEddsa := shared.Signers(c.Public.SignerPkHashes)
	// The zero-tag resolver is algorithm independent, and ed25519.Verify already asserts the signature.
	inputOwners := shared.HiddenOwnerSigners(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		authorizedEddsa,
		hiddenOwner,
	)
	shared.AssertHiddenRingOwner(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		authorizedEddsa,
		hiddenOwner,
	)
	// A cache read publishes the commitment of the note it spends.
	api.AssertIsEqual(c.CachedInputs.TreeID, 0)
	for i := range c.CachedInputs.IsCached {
		api.AssertIsEqual(c.CachedInputs.IsCached[i], 0)
		api.AssertIsEqual(c.CachedInputs.ReadHashes[i], 0)
	}

	// 5. Bind private output owners and enforce the shared transaction relation.
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

const messageLimbBits = 128
