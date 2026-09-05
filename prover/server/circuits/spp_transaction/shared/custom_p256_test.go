package shared_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"zolana/prover/circuits/gadget"
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
			TreeSlots:                    a.TreeSlots,
			OutputTreeID:                 a.OutputTreeID,
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
	rewriteInputAsP256WithIdentity(t, assignment, inputIndex, p256OwnerPkHash(t, ownerPrivateKey))
}

// rewriteInputAsP256WithIdentity marks the input as P256-owned (zero owner
// tag) and derives its UTXO owner from an explicit identity, so a test can
// supply a wrongly derived identity the in-circuit owner must not reproduce.
func rewriteInputAsP256WithIdentity(
	t testing.TB,
	assignment *testAssignment,
	inputIndex int,
	ownerPkHash *big.Int,
) {
	t.Helper()
	nullifierPk := spptest.MustNullifierPk(
		t,
		spptest.AsBigInt(assignment.Inputs[inputIndex].NullifierSecret),
	)
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
	ownerPkHash := p256OwnerPkHash(t, publicKeyPrivate)
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
	refreshCustomRingP256PublicInputHashWithOwner(
		t,
		assignment,
		messageDigest,
		defaultP256OwnerPkHash(assignment, p256PkHash),
	)
}

// refreshCustomRingP256PublicInputHashWithOwner recomputes the public-input
// hash with an explicit value for the published default P256 owner field, so a
// test can claim a publication the circuit must refuse.
func refreshCustomRingP256PublicInputHashWithOwner(
	t testing.TB,
	assignment *testAssignment,
	messageDigest [32]byte,
	publishedP256Owner *big.Int,
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
		spptest.MustTreeSlotsHashChain(t, treeSlotsToProtocol(assignment.TreeSlots)),
		spptest.AsBigInt(assignment.OutputTreeID),
		spptest.AsBigInt(assignment.PrivateTxHash),
		messageHash,
		publishedP256Owner,
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

// defaultP256OwnerPkHash mirrors the public field the circuit binds: the P256
// identity while a spent default-ring UTXO belongs to it, zero otherwise.
// Address slots never publish the identity.
func defaultP256OwnerPkHash(assignment *testAssignment, p256PkHash *big.Int) *big.Int {
	for _, input := range assignment.Inputs {
		domain := spptest.AsBigInt(input.Utxo.Domain).Int64()
		if domain == UtxoDomain &&
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

// rewriteOutputAsP256 makes output slot outputIndex owned by the shared P256
// key. A default-ring output then publishes the P256 identity through the
// published owner vector; a ring output keeps it private.
func rewriteOutputAsP256(
	t testing.TB,
	assignment *testAssignment,
	outputIndex int,
	ownerPrivateKey *ecdsa.PrivateKey,
) {
	t.Helper()
	ownerPkHash := p256OwnerPkHash(t, ownerPrivateKey)
	nullifierPk := spptest.AsBigInt(assignment.Outputs[outputIndex].NullifierPk)
	owner, err := protocol.OwnerHash(ownerPkHash, nullifierPk)
	if err != nil {
		t.Fatalf("P256 owner hash: %v", err)
	}
	assignment.Outputs[outputIndex].Utxo.Owner = owner
	assignment.Outputs[outputIndex].OwnerPkHash = ownerPkHash
	rebuildAfterOwnerChange(t, assignment)
}

// A ring P256 input is an anonymous spend. Spending a default-ring P256 UTXO
// in the same proof would publish the shared key next to the ring nullifier.
func TestCustomRingP256RejectsRingSpendWithDefaultP256Input(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	rewriteInputAsP256(t, assignment, 1, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rebuildAfterOwnerChange(t, assignment)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingFailed(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// Two default-ring P256 inputs publish the owner once, which is the sanctioned
// confidential default-ring spend.
func TestCustomRingP256AcceptsTwoDefaultP256Inputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	rewriteInputAsP256(t, assignment, 1, owner)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// A default-ring output owned by the shared key publishes the identity, so it
// cannot sit next to a ring P256 spend.
func TestCustomRingP256RejectsRingSpendPublishingP256Output(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rewriteOutputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingFailed(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// A ring P256 spend may pay the shared key inside the ring: the output owner
// stays private, so nothing links the spend to the identity.
func TestCustomRingP256AcceptsRingSpendToRingP256Output(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rewriteOutputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// Moving a default-ring P256 UTXO into the ring publishes the depositor, not a
// ring spender, so the mixed transaction stays allowed.
func TestCustomRingP256AcceptsDefaultP256DepositIntoRing(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rewriteOutputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// p256OwnerPkHash is the tagged P256 owner identity,
// hash_bytes_33(P256OwnerTag || x). It is a temporary local mirror of the
// gadget: delete it once prover-test/spp/protocol.OwnerPkField adopts the
// tagged derivation and call that instead.
func p256OwnerPkHash(t testing.TB, ownerPrivateKey *ecdsa.PrivateKey) *big.Int {
	t.Helper()
	return hashP256X(t, ownerPrivateKey, gadget.P256OwnerTag)
}

// solanaOwnerTag is the program-side tag of an SVM signer identity. A P256
// x-coordinate hashed under it must not pass as the P256 owner.
const solanaOwnerTag = 0x53

// hashP256X hashes the owner's 32-byte big-endian x-coordinate behind the
// given tag bytes; no tag yields the pre-fix untagged hash_bytes_32(x).
func hashP256X(t testing.TB, ownerPrivateKey *ecdsa.PrivateKey, tag ...byte) *big.Int {
	t.Helper()
	var x [32]byte
	ownerPrivateKey.PublicKey.X.FillBytes(x[:])
	identity, err := protocol.HashBytes(append(tag, x[:]...))
	if err != nil {
		t.Fatalf("P256 x hash: %v", err)
	}
	return identity
}

func TestCustomRingP256RejectsUntaggedOwnerIdentity(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256WithIdentity(t, assignment, 0, hashP256X(t, owner))
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingFailed(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingP256RejectsSolanaTaggedOwnerIdentity(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256WithIdentity(t, assignment, 0, hashP256X(t, owner, solanaOwnerTag))
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingFailed(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// p256DummyOutputAssignment pads a P256 transaction with a dummy output whose
// published tag is tag. The single input is owned by owner; inRing places the
// spend in the policy ring, which keeps the shared identity private.
func p256DummyOutputAssignment(
	t testing.TB,
	shape protocol.Shape,
	owner *ecdsa.PrivateKey,
	inRing bool,
	tag frontend.Variable,
) (*testAssignment, p256Authorization) {
	t.Helper()
	assignment := dummyOutputAssignment(t, shape)
	rewriteInputAsP256(t, assignment, 0, owner)
	if inRing {
		assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
		rebuildAfterOwnerChange(t, assignment)
	}
	tagDummyOutput(t, assignment, tag)
	authorization := authorizeP256(t, assignment, owner, owner)
	return assignment, authorization
}

// A ring P256 spend keeps the shared identity private, so a dummy output may
// not publish it: the copy would deanonymize the spender. Both the dummy-tag
// rule and AssertDefaultP256Owner reject this; the unit test in
// owner_tags_test.go isolates the dummy-tag rule.
func TestCustomRingP256RejectsDummyOutputNamingRingSpender(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	owner := spptest.FixedP256Key(t, 11)

	// Control: the same ring spend solves with an anonymous dummy.
	assignment, authorization := p256DummyOutputAssignment(t, shape, owner, true, 0)
	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)

	assignment, authorization = p256DummyOutputAssignment(t, shape, owner, true, p256OwnerPkHash(t, owner))
	assert.SolvingFailed(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// A default-ring P256 input already publishes the shared identity, so a dummy
// may repeat it.
func TestCustomRingP256AcceptsDummyOutputNamingPublishedP256Owner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	owner := spptest.FixedP256Key(t, 11)
	assignment, authorization := p256DummyOutputAssignment(t, shape, owner, false, p256OwnerPkHash(t, owner))

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// makeP256AddressSlot turns input idx into an address slot owned by the shared
// P256 owner. The zero owner tag selects the P256 key; the owner hash binds
// its pk field.
func makeP256AddressSlot(
	t testing.TB,
	assignment *testAssignment,
	idx int,
	owner *ecdsa.PrivateKey,
	seed *big.Int,
) {
	t.Helper()
	setAddressSlot(t, &assignment.Inputs[idx], p256OwnerPkHash(t, owner), spptest.Fe(0), seed)
}

// p256AddressAssignment spends a P256 UTXO in input 0 and creates a P256
// address in input 1, both owned by the same key. inRing places the spend in
// the policy ring; the address always sits in the default ring.
func p256AddressAssignment(t testing.TB, inRing bool) (*testAssignment, p256Authorization) {
	t.Helper()
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	solAsset := protocol.SolAsset()
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100)),
			sampleUtxoWithAssetAndAmount(20, solAsset, spptest.Fe(0)),
		},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(100))),
	)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	if inRing {
		assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
		rebuildAfterOwnerChange(t, assignment)
	}
	makeP256AddressSlot(t, assignment, 1, owner, spptest.Fe(0xABCDEF))
	finalizeAddressAssignment(t, assignment, true, false)
	return assignment, authorizeP256(t, assignment, owner, owner)
}

// p256AddressOnlyAssignment creates a single P256 address and spends nothing.
func p256AddressOnlyAssignment(t testing.TB) (*testAssignment, p256Authorization) {
	t.Helper()
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAsset := protocol.SolAsset()
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(0))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(0))),
	)
	owner := spptest.FixedP256Key(t, 11)
	makeP256AddressSlot(t, assignment, 0, owner, spptest.Fe(0xABCDEF))
	finalizeAddressAssignment(t, assignment, true, false)
	return assignment, authorizeP256(t, assignment, owner, owner)
}

// claimingPublishedP256Owner rebuilds the witness with the shared identity
// forced into the public default-owner field and its public-input hash.
func claimingPublishedP256Owner(
	t testing.TB,
	assignment *testAssignment,
	authorization p256Authorization,
) frontend.Circuit {
	t.Helper()
	var digest [32]byte
	authorization.high.FillBytes(digest[:16])
	authorization.low.FillBytes(digest[16:])
	refreshCustomRingP256PublicInputHashWithOwner(t, assignment, digest, authorization.pkHash)
	circuit := asCustomRingP256(assignment, authorization).(*customring.CustomRingP256Circuit)
	circuit.Public.DefaultP256OwnerPkHash = authorization.pkHash
	return circuit
}

// A ring P256 spender may create an address in the same proof. The address
// always carries ring id 0, but it spends nothing, so it neither counts as a
// default-ring input nor publishes the shared identity.
func TestCustomRingP256AcceptsAddressDuringRingSpend(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewCustomRingP256Circuit(Shape(protocol.Shape{NInputs: 2, NOutputs: 2}))
	assignment, authorization := p256AddressAssignment(t, true)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingFailed(
		circuit,
		claimingPublishedP256Owner(t, assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// A default-ring P256 spend publishes the identity regardless of an address
// slot beside it.
func TestCustomRingP256PublishesOwnerForDefaultSpendWithAddress(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewCustomRingP256Circuit(Shape(protocol.Shape{NInputs: 2, NOutputs: 2}))
	assignment, authorization := p256AddressAssignment(t, false)
	if defaultP256OwnerPkHash(assignment, authorization.pkHash).Sign() == 0 {
		t.Fatal("default-ring P256 spend must publish the shared owner")
	}

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// Creating an address alone spends nothing and publishes nothing: the public
// default-owner field must be zero even though the address sits in ring 0.
func TestCustomRingP256AddressOnlyKeepsOwnerPrivate(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewCustomRingP256Circuit(Shape(protocol.Shape{NInputs: 1, NOutputs: 2}))
	assignment, authorization := p256AddressOnlyAssignment(t)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingFailed(
		circuit,
		claimingPublishedP256Owner(t, assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// The payer is excluded from dummy markers on this rail as well.
func TestCustomRingP256RejectsDummyOutputPayerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	owner := spptest.FixedP256Key(t, 11)
	assignment, authorization := p256DummyOutputAssignment(t, shape, owner, false, testPayerPkHash())

	assert.SolvingFailed(
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
