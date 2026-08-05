package shared_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	customzone "zolana/prover/circuits/spp_transaction/custom"
	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type p256Authorization struct {
	pub    customzone.P256PublicKey
	sig    customzone.P256Signature
	low    *big.Int
	high   *big.Int
	pkHash *big.Int
}

func MustNewCustomZoneP256Circuit(shape Shape) *customzone.CustomZoneP256Circuit {
	circuit, err := customzone.NewCustomZoneP256Circuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func asCustomZoneP256(a *testAssignment, authorization p256Authorization) frontend.Circuit {
	return &customzone.CustomZoneP256Circuit{
		Public: customzone.CustomZoneP256Public{
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
			ZoneProgramID:                a.ZoneProgramID,
			AllowDummyInputs:             a.AllowDummyInputs,
			SignerPkHashes:               a.TransactionSignerPkHashes(),
			PublishedOutputOwnerPkHashes: a.PublishedOutputOwnerPkHashes(),
			PublicInputHash:              a.PublicInputHash,
		},
		Private: customzone.CustomZoneP256Private{
			Inputs:              a.coreInputs(),
			InputOwnerPkHashes:  a.InputOwnerPkHashes(),
			Outputs:             a.outputUtxos(),
			OutputOwnerPkHashes: a.OutputOwnerPkHashes(),
			OutputNullifierPks:  a.outputNullifierPks(),
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
		sig: customzone.P256Signature{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		low:    low,
		high:   high,
		pkHash: ownerPkHash,
	}
	refreshCustomZoneP256PublicInputHash(t, assignment, digest, ownerPkHash)
	return authorization
}

func refreshCustomZoneP256PublicInputHash(
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
	publicInputs := protocol.PublicInputs{
		Nullifiers:          spptest.ToBigInts(assignment.InputNullifiers()),
		OutputUtxoHashes:    spptest.ToBigInts(assignment.OutputHashes()),
		UtxoTreeRoots:       spptest.ToBigInts(assignment.InputUtxoRoots()),
		NullifierTreeRoots:  spptest.ToBigInts(assignment.InputNullifierTreeRoots()),
		PrivateTxHash:       spptest.AsBigInt(assignment.PrivateTxHash),
		ExternalDataHash:    spptest.AsBigInt(assignment.ExternalDataHash),
		ZoneProgramID:       spptest.AsBigInt(assignment.ZoneProgramID),
		AllowDummyInputs:    spptest.AsBigInt(assignment.AllowDummyInputs),
		SignerPkHashes:      spptest.ToBigInts(assignment.TransactionSignerPkHashes()),
		BindOutputOwnerTags: true,
		OutputOwnerPkHashes: spptest.ToBigInts(assignment.PublishedOutputOwnerPkHashes()),
	}
	for i := 0; i < NPublicSlots; i++ {
		publicInputs.PublicAssets[i] = spptest.AsBigInt(assignment.PublicAssets[i])
		publicInputs.PublicAmounts[i] = spptest.AsBigInt(assignment.PublicAmounts[i])
	}
	hash, err := protocol.PublicInputHashP256(
		publicInputs,
		messageHash,
		defaultP256OwnerPkHash(assignment, p256PkHash),
	)
	assignment.PublicInputHash = spptest.MustHash(t, hash, err)
}

func defaultP256OwnerPkHash(assignment *testAssignment, p256PkHash *big.Int) *big.Int {
	for _, input := range assignment.Inputs {
		domain := spptest.AsBigInt(input.Utxo.Domain).Int64()
		if (domain == UtxoDomain || domain == AddressDomain) &&
			spptest.AsBigInt(input.OwnerPkHash).Sign() == 0 &&
			spptest.AsBigInt(input.Utxo.ZoneProgramID).Sign() == 0 {
			return new(big.Int).Set(p256PkHash)
		}
	}
	return big.NewInt(0)
}

func TestCustomZoneP256Solves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomZoneP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomZoneP256KeepsZoneOnlyOwnerPrivate(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.ZoneProgramID = assignment.ZoneProgramID
	rebuildAfterOwnerChange(t, assignment)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomZoneP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomZoneP256AcceptsMixedOwners(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomZoneP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomZoneP256RejectsBadSignature(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	wrongSigner := spptest.FixedP256Key(t, 12)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, wrongSigner)

	assert.SolvingFailed(
		circuit,
		asCustomZoneP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomZoneP256RejectsBadMessageHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)
	authorization.low = new(big.Int).Add(authorization.low, big.NewInt(1))

	var changedDigest [32]byte
	authorization.high.FillBytes(changedDigest[:16])
	authorization.low.FillBytes(changedDigest[16:])
	refreshCustomZoneP256PublicInputHash(t, assignment, changedDigest, authorization.pkHash)

	assert.SolvingFailed(
		circuit,
		asCustomZoneP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomZoneP256RejectsOwnerKeyMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	otherOwner := spptest.FixedP256Key(t, 12)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, otherOwner, otherOwner)

	assert.SolvingFailed(
		circuit,
		asCustomZoneP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomZoneP256RejectsOffCurvePublicKey(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)
	authorization.pub = customzone.P256PublicKey{
		X: emulated.ValueOf[emulated.P256Fp](1),
		Y: emulated.ValueOf[emulated.P256Fp](1),
	}

	assert.SolvingFailed(
		circuit,
		asCustomZoneP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}
