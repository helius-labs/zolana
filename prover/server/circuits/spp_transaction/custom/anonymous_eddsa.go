package customring

import (
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/ed25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Properties:
// 1. Public: EdDSA input owners, default-ring input and output owners, and public asset transfers.
// 2. Private: custom-ring hidden input owners, custom-ring output owners, UTXO amounts, and UTXO assets.
// 3. The circuit verifies each hidden owner's Ed25519 signature; the Solana runtime verifies EdDSA co-signers.
//    The hidden owner identities share the Solana identity hash, so they are asserted distinct from every
//    signer and from each other.
// 6. Shape.NHiddenOwners hidden owners sign the same message. Each hidden input names its owner by a
//    private index, and every hidden owner spends at least one input.
// 4. Dummy slots are indistinguishable from real UTXO and address slots.
// 5. Input nullifiers are distinct and balances are preserved.

const messageLimbBits = 128

type CustomRingAnonymousEddsaPublic struct {
	Nullifiers                   []frontend.Variable
	OutputHashes                 []frontend.Variable
	TreeSlots                    []shared.TreeSlot
	OutputTreeID                 frontend.Variable
	PrivateTxHash                frontend.Variable
	MessageHashLow               frontend.Variable
	MessageHashHigh              frontend.Variable
	DefaultOwnerPkHash           frontend.Variable
	ExternalDataHash             frontend.Variable
	PublicAssets                 [shared.NPublicSlots]frontend.Variable
	PublicAmounts                [shared.NPublicSlots]frontend.Variable
	RingProgramID                frontend.Variable
	InputFlags                   frontend.Variable
	SignerPkHashes               []frontend.Variable
	PublishedOutputOwnerPkHashes []frontend.Variable
	PublicInputHash              frontend.Variable `gnark:",public"`
}

type CustomRingAnonymousEddsaPrivate struct {
	Inputs              []shared.Input
	InputOwnerPkHashes  []frontend.Variable
	Outputs             []shared.UtxoCircuitFields
	OutputOwnerPkHashes []frontend.Variable
	OutputNullifierPks  []frontend.Variable
	BlindingSeed        frontend.Variable
	// The first hidden owner. A single-owner circuit has only this one.
	OwnerPublicKey [32]frontend.Variable
	OwnerSignature [64]frontend.Variable
	// Hidden owners 1..NHiddenOwners-1, empty for a single owner. They follow
	// every other wire, so a single-owner witness keeps its committed layout.
	AdditionalOwnerPublicKeys [][32]frontend.Variable
	AdditionalOwnerSignatures [][64]frontend.Variable
	// InputHiddenOwners[i] is the index of the hidden owner of input i, 0 for
	// a non-hidden input. Empty for a single owner.
	InputHiddenOwners []frontend.Variable
}

type CustomRingAnonymousEddsaCircuit struct {
	CachedInputs shared.CachedInputs

	Shape   shared.Shape `gnark:"-"`
	Public  CustomRingAnonymousEddsaPublic
	Private CustomRingAnonymousEddsaPrivate
}

// NewCustomRingAnonymousEddsaCircuit sizes the circuit from the shape, including
// the public signer vector width.
func NewCustomRingAnonymousEddsaCircuit(shape shared.Shape) (*CustomRingAnonymousEddsaCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomRingAnonymousEddsaCircuit{
		CachedInputs: shared.NewCachedInputs(shape.NInputs),
		Shape:        shape,
		Public: CustomRingAnonymousEddsaPublic{
			Nullifiers:                   make([]frontend.Variable, shape.NInputs),
			OutputHashes:                 make([]frontend.Variable, shape.NOutputs),
			TreeSlots:                    shared.NewTreeSlots(),
			SignerPkHashes:               make([]frontend.Variable, shape.SignerWidth),
			PublishedOutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
		},
		Private: CustomRingAnonymousEddsaPrivate{
			Inputs:                    shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes:        make([]frontend.Variable, shape.NInputs),
			Outputs:                   make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputOwnerPkHashes:       make([]frontend.Variable, shape.NOutputs),
			OutputNullifierPks:        make([]frontend.Variable, shape.NOutputs),
			AdditionalOwnerPublicKeys: make([][32]frontend.Variable, shape.NHiddenOwners-1),
			AdditionalOwnerSignatures: make([][64]frontend.Variable, shape.NHiddenOwners-1),
			InputHiddenOwners:         make([]frontend.Variable, hiddenOwnerIndexCount(shape)),
		},
	}, nil
}

// hiddenOwnerIndexCount is the number of per-input owner indices: one per
// input once there is more than one hidden owner to choose from.
func hiddenOwnerIndexCount(shape shared.Shape) int {
	if shape.NHiddenOwners == 1 {
		return 0
	}
	return shape.NInputs
}

func (c *CustomRingAnonymousEddsaCircuit) transaction(
	api frontend.API,
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
		RingProgramID:     c.Public.RingProgramID,
		SignerPkHashChain: gadget.RightHashChain(api, c.Public.SignerPkHashes),
		InputFlags:        c.Public.InputFlags,
		PublicInputHash:   c.Public.PublicInputHash,
		PreimageAfterPrivateTxHash: []frontend.Variable{
			messageHash,
			c.Public.DefaultOwnerPkHash,
		},
		PreimageTail: []frontend.Variable{
			gadget.RightHashChain4(api, c.Public.PublishedOutputOwnerPkHashes),
		},
	}
}

func (c *CustomRingAnonymousEddsaCircuit) Define(api frontend.API) error {
	if c.Shape.NHiddenOwners != 1 {
		return c.defineHiddenOwners(api)
	}
	hiddenOwner, messageHash := c.ownerAuthorization(api)
	tx := c.transaction(api, messageHash)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: c.Shape.SignerWidth},
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

	authorizedEddsa := shared.Signers(c.Public.SignerPkHashes)
	for _, signer := range authorizedEddsa {
		api.AssertIsDifferent(signer, hiddenOwner)
	}
	// ed25519.Verify asserts the signature.
	inputOwners := shared.HiddenOwnerSigners(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		authorizedEddsa,
		hiddenOwner,
		1,
	)
	shared.AssertDefaultHiddenOwner(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		c.Public.PublishedOutputOwnerPkHashes,
		hiddenOwner,
		c.Public.DefaultOwnerPkHash,
	)
	authorized := append(shared.Signers(nil), authorizedEddsa...)
	authorized = append(authorized, hiddenOwner)
	outputPubkeyIsSigner := authorized.ContainsEach(api, c.Private.OutputOwnerPkHashes)
	if err := shared.AssertPublishedOutputOwners(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		c.Public.PublishedOutputOwnerPkHashes,
	); err != nil {
		return err
	}
	// A dummy may repeat the hidden identity only while a default-ring
	// hidden input already publishes it; a ring spend keeps it out of the set.
	dummyIdentities := append(shared.Signers(nil), authorizedEddsa...)
	dummyIdentities = append(dummyIdentities, c.Public.DefaultOwnerPkHash)
	if err := shared.AssertMaskedDummyOutputTags(
		api,
		tx.Outputs,
		tx.OutputIsCompact,
		c.Public.PublishedOutputOwnerPkHashes,
		dummyIdentities,
	); err != nil {
		return err
	}

	return tx.Constrain(api, inputOwners, outputPubkeyIsSigner)
}

func (c *CustomRingAnonymousEddsaCircuit) ownerAuthorization(
	api frontend.API,
) (frontend.Variable, frontend.Variable) {
	messageBits := append(
		api.ToBinary(c.Public.MessageHashLow, messageLimbBits),
		api.ToBinary(c.Public.MessageHashHigh, messageLimbBits)...,
	)
	// The message digest is not an identity, so it stays an untagged hash_bytes_32.
	messageBytes := bytes32FromBits(api, messageBits)
	key := ed25519.Verify(api, ed25519.Inputs{
		PublicKey: c.Private.OwnerPublicKey,
		Signature: c.Private.OwnerSignature,
		Message:   messageBytes[:],
	})
	// Verify's SHA-512 transcript range-checks the key and message bytes.
	return gadget.SolanaOwnerIdentityBounded(api, key), gadget.HashBoundedBytes(api, messageBytes[:])
}

// defineHiddenOwners constrains a circuit with more than one hidden owner. It
// mirrors Define with the per-owner rules of shared.AssertDefaultHiddenOwners
// and shared.HiddenOwnersSigners.
func (c *CustomRingAnonymousEddsaCircuit) defineHiddenOwners(api frontend.API) error {
	if err := c.validateHiddenOwnerLayout(); err != nil {
		return err
	}
	hiddenOwners, messageHash := c.ownersAuthorization(api)
	tx := c.transaction(api, messageHash)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: c.Shape.SignerWidth},
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

	authorizedEddsa := shared.Signers(c.Public.SignerPkHashes)
	shared.AssertDistinctHiddenOwners(api, hiddenOwners, authorizedEddsa)
	selectors := shared.HiddenOwnerSelectors(api, c.Private.InputHiddenOwners, c.Shape.NHiddenOwners)
	inputOwners := shared.HiddenOwnersSigners(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		authorizedEddsa,
		hiddenOwners,
		selectors,
	)
	publishedOwners := shared.AssertDefaultHiddenOwners(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		selectors,
		c.Public.PublishedOutputOwnerPkHashes,
		hiddenOwners,
		c.Public.DefaultOwnerPkHash,
	)
	authorized := append(shared.Signers(nil), authorizedEddsa...)
	authorized = append(authorized, hiddenOwners...)
	outputPubkeyIsSigner := authorized.ContainsEach(api, c.Private.OutputOwnerPkHashes)
	if err := shared.AssertPublishedOutputOwners(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		c.Public.PublishedOutputOwnerPkHashes,
	); err != nil {
		return err
	}
	// A dummy may repeat a hidden identity only while that owner's default-ring
	// hidden input already publishes it.
	dummyIdentities := append(shared.Signers(nil), authorizedEddsa...)
	dummyIdentities = append(dummyIdentities, publishedOwners...)
	if err := shared.AssertMaskedDummyOutputTags(
		api,
		tx.Outputs,
		tx.OutputIsCompact,
		c.Public.PublishedOutputOwnerPkHashes,
		dummyIdentities,
	); err != nil {
		return err
	}

	return tx.Constrain(api, inputOwners, outputPubkeyIsSigner)
}

func (c *CustomRingAnonymousEddsaCircuit) validateHiddenOwnerLayout() error {
	additional := c.Shape.NHiddenOwners - 1
	for _, check := range []shared.LengthCheck{
		{Name: "additional owner public key", Got: len(c.Private.AdditionalOwnerPublicKeys), Want: additional},
		{Name: "additional owner signature", Got: len(c.Private.AdditionalOwnerSignatures), Want: additional},
		{Name: "input hidden owner", Got: len(c.Private.InputHiddenOwners), Want: hiddenOwnerIndexCount(c.Shape)},
	} {
		if err := shared.ValidateLength(check.Name, check.Got, check.Want); err != nil {
			return err
		}
	}
	return nil
}

// ownersAuthorization verifies every hidden owner's signature over the one
// message and returns the owners' identities in order and the message hash.
func (c *CustomRingAnonymousEddsaCircuit) ownersAuthorization(
	api frontend.API,
) ([]frontend.Variable, frontend.Variable) {
	messageBits := append(
		api.ToBinary(c.Public.MessageHashLow, messageLimbBits),
		api.ToBinary(c.Public.MessageHashHigh, messageLimbBits)...,
	)
	messageBytes := bytes32FromBits(api, messageBits)
	keys := append([][32]frontend.Variable{c.Private.OwnerPublicKey}, c.Private.AdditionalOwnerPublicKeys...)
	signatures := append([][64]frontend.Variable{c.Private.OwnerSignature}, c.Private.AdditionalOwnerSignatures...)
	owners := make([]frontend.Variable, len(keys))
	for j := range keys {
		key := ed25519.Verify(api, ed25519.Inputs{
			PublicKey: keys[j],
			Signature: signatures[j],
			Message:   messageBytes[:],
		})
		owners[j] = gadget.SolanaOwnerIdentityBounded(api, key)
	}
	return owners, gadget.HashBoundedBytes(api, messageBytes[:])
}

// bytes32FromBits adapts a 256-bit little-endian bit decomposition to the
// big-endian byte order the byte-oriented hash gadgets expect.
func bytes32FromBits(api frontend.API, bits []frontend.Variable) [32]frontend.Variable {
	var bytes [32]frontend.Variable
	for i := range bytes {
		bytes[len(bytes)-1-i] = api.FromBinary(bits[i*8 : (i+1)*8]...)
	}
	return bytes
}
