package customring

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// Properties:
// 1. Public: EdDSA input owners, default-ring input and output owners, and public asset transfers.
// 2. Private: custom-ring P256 input owners, custom-ring output owners, UTXO amounts, and UTXO assets.
// 3. The circuit verifies the shared P256 signature; the Solana runtime verifies EdDSA co-signers.
//    The shared P256 owner identity is the algorithm-tagged hash_bytes_33 over the
//    x-coordinate (gadget.P256OwnerIdentity), so it cannot equal any Solana signer identity.
// 4. Dummy slots are indistinguishable from real UTXO and address slots.
// 5. Input nullifiers are distinct and balances are preserved.

const (
	p256MessageLimbBits = 128
	p256WitnessLimbBits = 64
)

type (
	P256PublicKey = gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	P256Signature = gnarkecdsa.Signature[emulated.P256Fr]
)

type CustomRingP256Public struct {
	Nullifiers                   []frontend.Variable
	OutputHashes                 []frontend.Variable
	TreeSlots                    []shared.TreeSlot
	OutputTreeID                 frontend.Variable
	PrivateTxHash                frontend.Variable
	P256MessageHashLow           frontend.Variable
	P256MessageHashHigh          frontend.Variable
	DefaultP256OwnerPkHash       frontend.Variable
	ExternalDataHash             frontend.Variable
	PublicAssets                 [shared.NPublicSlots]frontend.Variable
	PublicAmounts                [shared.NPublicSlots]frontend.Variable
	RingProgramID                frontend.Variable
	InputFlags                   frontend.Variable
	SignerPkHashes               []frontend.Variable
	PublishedOutputOwnerPkHashes []frontend.Variable
	PublicInputHash              frontend.Variable `gnark:",public"`
}

type CustomRingP256Private struct {
	Inputs              []shared.Input
	InputOwnerPkHashes  []frontend.Variable
	Outputs             []shared.UtxoCircuitFields
	OutputOwnerPkHashes []frontend.Variable
	OutputNullifierPks  []frontend.Variable
	BlindingSeed        frontend.Variable
	P256Pub             P256PublicKey
	P256Sig             P256Signature
}

type CustomRingP256Circuit struct {
	CachedInputs shared.CachedInputs

	Shape   shared.Shape `gnark:"-"`
	Public  CustomRingP256Public
	Private CustomRingP256Private
}

func NewCustomRingP256Circuit(shape shared.Shape) (*CustomRingP256Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomRingP256Circuit{
		CachedInputs: shared.NewCachedInputs(shape.NInputs),
		Shape:        shape,
		Public: CustomRingP256Public{
			Nullifiers:                   make([]frontend.Variable, shape.NInputs),
			OutputHashes:                 make([]frontend.Variable, shape.NOutputs),
			TreeSlots:                    shared.NewTreeSlots(),
			SignerPkHashes:               make([]frontend.Variable, shape.SignerWidth()),
			PublishedOutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
		},
		Private: CustomRingP256Private{
			Inputs:              shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes:  make([]frontend.Variable, shape.NInputs),
			Outputs:             make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
			OutputNullifierPks:  make([]frontend.Variable, shape.NOutputs),
		},
	}, nil
}

func (c *CustomRingP256Circuit) transaction(
	api frontend.API,
	p256MessageHash frontend.Variable,
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
			p256MessageHash,
			c.Public.DefaultP256OwnerPkHash,
		},
		PreimageTail: []frontend.Variable{
			gadget.RightHashChain4(api, c.Public.PublishedOutputOwnerPkHashes),
		},
	}
}

func (c *CustomRingP256Circuit) Define(api frontend.API) error {
	p256PkHash, p256MessageHash, p256SignatureValid, err := c.p256Authorization(api)
	if err != nil {
		return err
	}
	tx := c.transaction(api, p256MessageHash)
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
	inputOwners := shared.P256Signers(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		authorizedEddsa,
		p256PkHash,
		p256SignatureValid,
	)
	shared.AssertDefaultP256Owner(
		api,
		tx.Inputs,
		c.Private.InputOwnerPkHashes,
		c.Public.PublishedOutputOwnerPkHashes,
		p256PkHash,
		c.Public.DefaultP256OwnerPkHash,
	)
	authorized := append(shared.Signers(nil), authorizedEddsa...)
	authorized = append(authorized, p256PkHash)
	outputPubkeyIsSigner := authorized.ContainsEach(api, c.Private.OutputOwnerPkHashes)
	if err := shared.AssertPublishedOutputOwners(
		api,
		tx.Outputs,
		c.Private.OutputOwnerPkHashes,
		c.Public.PublishedOutputOwnerPkHashes,
	); err != nil {
		return err
	}
	// A dummy may repeat the shared P256 identity only while a default-ring
	// P256 input already publishes it; a ring spend keeps it out of the set.
	dummyIdentities := append(shared.Signers(nil), authorizedEddsa.WithoutPayer()...)
	dummyIdentities = append(dummyIdentities, c.Public.DefaultP256OwnerPkHash)
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

// p256Authorization verifies the shared P256 signature unconditionally:
// P256Signers requires at least one P256 input on this rail, so a satisfiable
// witness always carries a valid signature.
func (c *CustomRingP256Circuit) p256Authorization(
	api frontend.API,
) (frontend.Variable, frontend.Variable, frontend.Variable, error) {
	messageBits := append(
		api.ToBinary(c.Public.P256MessageHashLow, p256MessageLimbBits),
		api.ToBinary(c.Public.P256MessageHashHigh, p256MessageLimbBits)...,
	)
	message := make([]frontend.Variable, len(messageBits)/p256WitnessLimbBits)
	for i := range message {
		message[i] = api.FromBinary(messageBits[i*p256WitnessLimbBits : (i+1)*p256WitnessLimbBits]...)
	}
	pub, sig := c.Private.P256Pub, c.Private.P256Sig
	publicKeyX := emcurve.VerifyECDSA(api, emcurve.ECDSAInputs{
		LimbBits:   p256WitnessLimbBits,
		PublicKeyX: pub.X.Limbs,
		PublicKeyY: pub.Y.Limbs,
		R:          sig.R.Limbs,
		S:          sig.S.Limbs,
		Message:    message,
	})
	p256PkHash := gadget.P256OwnerIdentity(api, publicKeyX)

	// The message digest is not an identity, so it stays an untagged hash_bytes_32.
	messageBytes := bytes32FromBits(api, messageBits)
	p256MessageHash := gadget.HashBytes(api, messageBytes[:])
	return p256PkHash, p256MessageHash, frontend.Variable(1), nil
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
