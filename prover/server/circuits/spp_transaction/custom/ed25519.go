package customring

import (
	"zolana/prover/circuits/ed25519"
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Properties:
// 1. Public: EdDSA input owners, default-ring input and output owners, and public asset transfers.
// 2. Private: custom-ring Ed25519 input owners, custom-ring output owners, UTXO amounts, and UTXO assets.
// 3. The circuit verifies the shared Ed25519 signature over the SPP signing digest; the Solana
//    runtime verifies EdDSA co-signers. The shared owner identity is the Solana-tagged
//    hash_bytes_33 over the public key (gadget.SolanaOwnerIdentity), the same identity a
//    runtime signer of that key has. A ring Ed25519 spend therefore requires that identity to
//    be absent from every public owner field, the signer vector included.
// 4. Dummy slots are indistinguishable from real UTXO and address slots.
// 5. Input nullifiers are distinct and balances are preserved.

const ed25519MessageLimbBits = 128

type CustomRingEd25519Public struct {
	Nullifiers                   []frontend.Variable
	OutputHashes                 []frontend.Variable
	TreeSlots                    []shared.TreeSlot
	OutputTreeID                 frontend.Variable
	PrivateTxHash                frontend.Variable
	Ed25519MessageHashLow        frontend.Variable
	Ed25519MessageHashHigh       frontend.Variable
	DefaultEd25519OwnerPkHash    frontend.Variable
	ExternalDataHash             frontend.Variable
	PublicAssets                 [shared.NPublicSlots]frontend.Variable
	PublicAmounts                [shared.NPublicSlots]frontend.Variable
	RingProgramID                frontend.Variable
	InputFlags                   frontend.Variable
	SignerPkHashes               []frontend.Variable
	PublishedOutputOwnerPkHashes []frontend.Variable
	PublicInputHash              frontend.Variable `gnark:",public"`
}

type CustomRingEd25519Private struct {
	Inputs              []shared.Input
	InputOwnerPkHashes  []frontend.Variable
	Outputs             []shared.UtxoCircuitFields
	OutputOwnerPkHashes []frontend.Variable
	OutputNullifierPks  []frontend.Variable
	BlindingSeed        frontend.Variable
	Ed25519PublicKey    [32]frontend.Variable
	Ed25519Signature    [64]frontend.Variable
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
			Nullifiers:                   make([]frontend.Variable, shape.NInputs),
			OutputHashes:                 make([]frontend.Variable, shape.NOutputs),
			TreeSlots:                    shared.NewTreeSlots(),
			SignerPkHashes:               make([]frontend.Variable, shape.SignerWidth()),
			PublishedOutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
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

func (c *CustomRingEd25519Circuit) transaction(
	api frontend.API,
	ed25519MessageHash frontend.Variable,
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
			ed25519MessageHash,
			c.Public.DefaultEd25519OwnerPkHash,
		},
		PreimageTail: []frontend.Variable{
			gadget.RightHashChain4(api, c.Public.PublishedOutputOwnerPkHashes),
		},
	}
}

func (c *CustomRingEd25519Circuit) Define(api frontend.API) error {
	ed25519PkHash, ed25519MessageHash := c.ed25519Authorization(api)
	tx := c.transaction(api, ed25519MessageHash)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: c.Shape.SignerWidth()},
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
	inputOwners := shared.Ed25519Signers(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		authorizedEddsa,
		ed25519PkHash,
	)
	shared.AssertDefaultEd25519Owner(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		c.Public.PublishedOutputOwnerPkHashes,
		authorizedEddsa,
		ed25519PkHash,
		c.Public.DefaultEd25519OwnerPkHash,
	)
	authorized := append(shared.Signers(nil), authorizedEddsa...)
	authorized = append(authorized, ed25519PkHash)
	outputPubkeyIsSigner := authorized.ContainsEach(api, c.Private.OutputOwnerPkHashes)
	if err := shared.AssertPublishedOutputOwners(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		c.Public.PublishedOutputOwnerPkHashes,
	); err != nil {
		return err
	}
	// A dummy may repeat the shared Ed25519 identity only while a default-ring
	// Ed25519 input or a public signer already publishes it; a ring spend keeps
	// it out of both (AssertDefaultEd25519Owner), so it stays out of the set.
	dummyIdentities := append(shared.Signers(nil), authorizedEddsa.WithoutPayer()...)
	dummyIdentities = append(dummyIdentities, c.Public.DefaultEd25519OwnerPkHash)
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

// ed25519Authorization verifies the shared Ed25519 signature unconditionally:
// Ed25519Signers requires at least one Ed25519 input on this rail, so a
// satisfiable witness always carries a valid signature. The signed message is
// the 32-byte digest itself, rebuilt big-endian from its public 128-bit halves.
func (c *CustomRingEd25519Circuit) ed25519Authorization(
	api frontend.API,
) (frontend.Variable, frontend.Variable) {
	messageBits := append(
		api.ToBinary(c.Public.Ed25519MessageHashLow, ed25519MessageLimbBits),
		api.ToBinary(c.Public.Ed25519MessageHashHigh, ed25519MessageLimbBits)...,
	)
	messageBytes := bytes32FromBits(api, messageBits)
	publicKey := ed25519.Verify(api, ed25519.Inputs{
		PublicKey: c.Private.Ed25519PublicKey,
		Signature: c.Private.Ed25519Signature,
		Message:   messageBytes[:],
	})
	ed25519PkHash := gadget.SolanaOwnerIdentity(api, publicKey)

	// The message digest is not an identity, so it stays an untagged hash_bytes_32.
	ed25519MessageHash := gadget.HashBytes(api, messageBytes[:])
	return ed25519PkHash, ed25519MessageHash
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
