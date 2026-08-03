package customring

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// Properties:
// 1. Public: EdDSA input owners, default-ring input and output owners, and public asset transfers.
// 2. Private: custom-ring P256 input owners, custom-ring output owners, UTXO amounts, and UTXO assets.
// 3. The circuit verifies the shared P256 signature; the Solana runtime verifies EdDSA co-signers.
// 4. Dummy slots are indistinguishable from real UTXO and address slots.
// 5. Input nullifiers are distinct and balances are preserved.

const p256MessageLimbBits = 128

type (
	P256PublicKey = gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	P256Signature = gnarkecdsa.Signature[emulated.P256Fr]
)

type CustomRingP256Public struct {
	Nullifiers                   []frontend.Variable
	OutputHashes                 []frontend.Variable
	UtxoTreeRoots                []frontend.Variable
	NullifierTreeRoots           []frontend.Variable
	PrivateTxHash                frontend.Variable
	P256MessageHashLow           frontend.Variable
	P256MessageHashHigh          frontend.Variable
	DefaultP256OwnerPkHash       frontend.Variable
	ExternalDataHash             frontend.Variable
	PublicAssets                 [shared.NPublicSlots]frontend.Variable
	PublicAmounts                [shared.NPublicSlots]frontend.Variable
	RingProgramID                frontend.Variable
	AllowDummyInputs             frontend.Variable
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
	P256Pub             P256PublicKey
	P256Sig             P256Signature
}

type CustomRingP256Circuit struct {
	Shape   shared.Shape `gnark:"-"`
	Public  CustomRingP256Public
	Private CustomRingP256Private
}

func NewCustomRingP256Circuit(shape shared.Shape) (*CustomRingP256Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomRingP256Circuit{
		Shape: shape,
		Public: CustomRingP256Public{
			Nullifiers:                   make([]frontend.Variable, shape.NInputs),
			OutputHashes:                 make([]frontend.Variable, shape.NOutputs),
			UtxoTreeRoots:                make([]frontend.Variable, shape.NInputs),
			NullifierTreeRoots:           make([]frontend.Variable, shape.NInputs),
			SignerPkHashes:               make([]frontend.Variable, shape.NInputs+1),
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
		Shape:              c.Shape,
		Nullifiers:         c.Public.Nullifiers,
		OutputHashes:       c.Public.OutputHashes,
		UtxoTreeRoots:      c.Public.UtxoTreeRoots,
		NullifierTreeRoots: c.Public.NullifierTreeRoots,
		Inputs:             c.Private.Inputs,
		Outputs:            c.Private.Outputs,
		PrivateTxHash:      c.Public.PrivateTxHash,
		ExternalDataHash:   c.Public.ExternalDataHash,
		PublicAssets:       c.Public.PublicAssets,
		PublicAmounts:      c.Public.PublicAmounts,
		RingProgramID:      c.Public.RingProgramID,
		SignerPkHashChain:  gadget.RightHashChain(api, c.Public.SignerPkHashes),
		AllowDummyInputs:   c.Public.AllowDummyInputs,
		PublicInputHash:    c.Public.PublicInputHash,
		PreimageAfterPrivateTxHash: []frontend.Variable{
			p256MessageHash,
			c.Public.DefaultP256OwnerPkHash,
		},
		PreimageTail: []frontend.Variable{
			gadget.HashChain(api, c.Public.PublishedOutputOwnerPkHashes),
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

	authorizedEddsa := shared.Signers(c.Public.SignerPkHashes)
	inputOwners, _ := shared.P256Signers(
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

func (c *CustomRingP256Circuit) p256Authorization(
	api frontend.API,
) (frontend.Variable, frontend.Variable, frontend.Variable, error) {
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](
		api,
		sw_emulated.GetCurveParams[emulated.P256Fp](),
	)
	if err != nil {
		return nil, nil, nil, err
	}
	point := sw_emulated.AffinePoint[emulated.P256Fp](c.Private.P256Pub)
	curve.AssertIsOnCurve(&point)

	fp, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		return nil, nil, nil, err
	}
	p256PkHash := hashBytes32Bits(api, fp.ToBitsCanonical(&point.X))

	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, nil, nil, err
	}
	messageBits := append(
		api.ToBinary(c.Public.P256MessageHashLow, p256MessageLimbBits),
		api.ToBinary(c.Public.P256MessageHashHigh, p256MessageLimbBits)...,
	)
	message := fr.FromBits(messageBits...)
	p256MessageHash := hashBytes32Bits(api, messageBits)
	p256SignatureValid := c.Private.P256Pub.IsValid(
		api,
		sw_emulated.GetCurveParams[emulated.P256Fp](),
		message,
		&c.Private.P256Sig,
	)
	return p256PkHash, p256MessageHash, p256SignatureValid, nil
}

// hashBytes32Bits adapts a little-endian bit decomposition to the existing
// byte-oriented HashBytes circuit helpers.
func hashBytes32Bits(api frontend.API, bits []frontend.Variable) frontend.Variable {
	bytes := make([]frontend.Variable, 32)
	for i := range bytes {
		bytes[len(bytes)-1-i] = api.FromBinary(bits[i*8 : (i+1)*8]...)
	}
	return gadget.HashBytes(api, bytes)
}
