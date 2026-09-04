package shared_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	customring "zolana/prover/circuits/spp_transaction/custom"
	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type p256Authorization struct {
	pub    customring.P256PublicKey
	sig    customring.P256Signature
	low    *big.Int
	high   *big.Int
	pkHash *big.Int
}

func MustNewCustomRingP256Circuit(shape Shape) *customring.CustomRingP256Circuit {
	circuit, err := customring.NewCustomRingP256Circuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func asCustomRingP256(a *testAssignment, authorization p256Authorization) frontend.Circuit {
	return &customring.CustomRingP256Circuit{
		Public: customring.CustomRingP256Public{
			Nullifiers:                   a.InputNullifiers(),
			OutputHashes:                 a.OutputHashes(),
			UtxoTreeRoots:                a.InputUtxoRoots(),
			NullifierTreeRoots:           a.InputNullifierTreeRoots(),
			PrivateTxHash:                a.PrivateTxHash,
			P256MessageHashLow:           authorization.low,
			P256MessageHashHigh:          authorization.high,
			DefaultP256OwnerPkHash:       defaultP256OwnerPkHash(a, authorization.pkHash),
			ExternalDataHash:             a.ExternalDataHash,
			PublicAssets:                 a.PublicAssets,
			PublicAmounts:                a.PublicAmounts,
			RingProgramID:                a.RingProgramID,
			AllowDummyInputs:             a.AllowDummyInputs,
			SignerPkHashes:               a.TransactionSignerPkHashes(),
			PublishedOutputOwnerPkHashes: a.PublishedOutputOwnerPkHashes(),
			PublicInputHash:              a.PublicInputHash,
		},
		Private: customring.CustomRingP256Private{
			Inputs:              a.coreInputs(),
			InputOwnerPkHashes:  a.InputOwnerPkHashes(),
			Outputs:             a.outputUtxos(),
			OutputOwnerPkHashes: a.OutputOwnerPkHashes(),
			OutputNullifierPks:  a.outputNullifierPks(),
			TxSecret:            a.TxSecret,
			P256Pub:             authorization.pub,
			P256Sig:             authorization.sig,
		},
	}
}

func rewriteInputAsP256(
	t testing.TB,
	assignment *testAssignment,
	inputIndex int,
	ownerPrivateKey *ecdsa.PrivateKey,
) {
	t.Helper()
	nullifierPk := spptest.MustNullifierPk(
		t,
		spptest.AsBigInt(assignment.Inputs[inputIndex].NullifierSecret),
	)
	compressed := elliptic.MarshalCompressed(
		elliptic.P256(),
		ownerPrivateKey.PublicKey.X,
		ownerPrivateKey.PublicKey.Y,
	)
	ownerPkHash, err := protocol.OwnerPkField(compressed)
	if err != nil {
		t.Fatalf("P256 owner pk hash: %v", err)
	}
	owner, err := protocol.OwnerHash(ownerPkHash, nullifierPk)
	if err != nil {
		t.Fatalf("P256 owner hash: %v", err)
	}
	assignment.Inputs[inputIndex].Utxo.Owner = owner
	assignment.Inputs[inputIndex].OwnerPkHash = spptest.Fe(0)
	rebuildAfterOwnerChange(t, assignment)
}

func authorizeP256(
	t testing.TB,
	assignment *testAssignment,
	publicKeyPrivate *ecdsa.PrivateKey,
	signingPrivate *ecdsa.PrivateKey,
) p256Authorization {
	t.Helper()
	var privateTxHash [32]byte
	spptest.AsBigInt(assignment.PrivateTxHash).FillBytes(privateTxHash[:])
	digest := sha256.Sum256(privateTxHash[:])
	low := new(big.Int).SetBytes(digest[16:])
	high := new(big.Int).SetBytes(digest[:16])
	r, s, err := ecdsa.Sign(rand.Reader, signingPrivate, digest[:])
	if err != nil {
		t.Fatalf("sign P256 transaction: %v", err)
	}
	compressed := elliptic.MarshalCompressed(
		elliptic.P256(),
		publicKeyPrivate.PublicKey.X,
		publicKeyPrivate.PublicKey.Y,
	)
	ownerPkHash, err := protocol.OwnerPkField(compressed)
	if err != nil {
		t.Fatalf("P256 owner pk hash: %v", err)
	}
	authorization := p256Authorization{
		pub: spptest.P256PubkeyAssignment(publicKeyPrivate),
		sig: customring.P256Signature{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		low:    low,
		high:   high,
		pkHash: ownerPkHash,
	}
	refreshCustomRingP256PublicInputHash(t, assignment, digest, ownerPkHash)
	return authorization
}

func refreshCustomRingP256PublicInputHash(
	t testing.TB,
	assignment *testAssignment,
	messageDigest [32]byte,
	p256PkHash *big.Int,
) {
	t.Helper()
	messageHash, err := protocol.HashBytes(messageDigest[:])
	if err != nil {
		t.Fatalf("P256 message hash: %v", err)
	}
	signerChain, err := protocol.RightHashChain(
		spptest.ToBigInts(assignment.TransactionSignerPkHashes()),
	)
	if err != nil {
		t.Fatalf("P256 signer chain: %v", err)
	}
	fields := []*big.Int{
		spptest.MustHashChain(t, spptest.ToBigInts(assignment.InputNullifiers())),
		spptest.MustHashChain(t, spptest.ToBigInts(assignment.OutputHashes())),
		spptest.MustHashChain(t, spptest.ToBigInts(assignment.InputUtxoRoots())),
		spptest.MustHashChain(t, spptest.ToBigInts(assignment.InputNullifierTreeRoots())),
		spptest.AsBigInt(assignment.PrivateTxHash),
		messageHash,
		defaultP256OwnerPkHash(assignment, p256PkHash),
		spptest.AsBigInt(assignment.ExternalDataHash),
	}
	for i := 0; i < NPublicSlots; i++ {
		fields = append(
			fields,
			spptest.AsBigInt(assignment.PublicAssets[i]),
			spptest.AsBigInt(assignment.PublicAmounts[i]),
		)
	}
	fields = append(
		fields,
		spptest.AsBigInt(assignment.RingProgramID),
		signerChain,
		spptest.AsBigInt(assignment.AllowDummyInputs),
		spptest.MustHashChain(t, spptest.ToBigInts(assignment.PublishedOutputOwnerPkHashes())),
	)
	assignment.PublicInputHash = spptest.MustHashChain(t, fields)
}

func defaultP256OwnerPkHash(assignment *testAssignment, p256PkHash *big.Int) *big.Int {
	for _, input := range assignment.Inputs {
		domain := spptest.AsBigInt(input.Utxo.Domain).Int64()
		if (domain == UtxoDomain || domain == AddressDomain) &&
			spptest.AsBigInt(input.OwnerPkHash).Sign() == 0 &&
			spptest.AsBigInt(input.Utxo.RingProgramID).Sign() == 0 {
			return new(big.Int).Set(p256PkHash)
		}
	}
	return big.NewInt(0)
}

func TestCustomRingP256Solves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingP256PublicInputHashBindsEveryField(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)

	var messageDigest [32]byte
	authorization.high.FillBytes(messageDigest[:16])
	authorization.low.FillBytes(messageDigest[16:])
	refreshHash := func() {
		refreshCustomRingP256PublicInputHash(t, assignment, messageDigest, authorization.pkHash)
	}
	extraMutations := []publicInputHashMutation{
		{name: "p256_message_hash_low", run: func() {
			changed := messageDigest
			changed[31] ^= 1
			refreshCustomRingP256PublicInputHash(t, assignment, changed, authorization.pkHash)
		}},
		{name: "p256_message_hash_high", run: func() {
			changed := messageDigest
			changed[0] ^= 1
			refreshCustomRingP256PublicInputHash(t, assignment, changed, authorization.pkHash)
		}},
		{name: "default_p256_owner_pk_hash", run: func() {
			original := assignment.Inputs[0].Utxo.RingProgramID
			assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
			refreshHash()
			assignment.Inputs[0].Utxo.RingProgramID = original
		}},
	}
	assertPublicInputHashBindsEveryField(
		t,
		circuit,
		assignment,
		func() frontend.Circuit { return asCustomRingP256(assignment, authorization) },
		refreshHash,
		publicInputHashBindingOptions{
			includeRingProgramID:       true,
			includeOutputOwnerPkHashes: true,
			signerWidth:                len(assignment.SignerPkHashes),
			extraMutations:             extraMutations,
		},
	)
}

func TestCustomRingP256KeepsRingOnlyOwnerPrivate(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rebuildAfterOwnerChange(t, assignment)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingP256AcceptsMixedOwners(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingP256RejectsBadSignature(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	wrongSigner := spptest.FixedP256Key(t, 12)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, wrongSigner)

	assert.SolvingFailed(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingP256RejectsBadMessageHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)
	authorization.low = new(big.Int).Add(authorization.low, big.NewInt(1))

	var changedDigest [32]byte
	authorization.high.FillBytes(changedDigest[:16])
	authorization.low.FillBytes(changedDigest[16:])
	refreshCustomRingP256PublicInputHash(t, assignment, changedDigest, authorization.pkHash)

	assert.SolvingFailed(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingP256RejectsOwnerKeyMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	otherOwner := spptest.FixedP256Key(t, 12)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, otherOwner, otherOwner)

	assert.SolvingFailed(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingP256RejectsOffCurvePublicKey(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)
	authorization.pub = customring.P256PublicKey{
		X: emulated.ValueOf[emulated.P256Fp](1),
		Y: emulated.ValueOf[emulated.P256Fp](1),
	}

	assert.SolvingFailed(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}
