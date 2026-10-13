package shared_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"math/big"
	"testing"

	customring "zolana/prover/circuits/spp_transaction/custom"
	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type ed25519Authorization struct {
	pub    [32]byte
	sig    [64]byte
	low    *big.Int
	high   *big.Int
	pkHash *big.Int
}

func MustNewCustomRingEd25519Circuit(shape Shape) *customring.CustomRingEd25519Circuit {
	circuit, err := customring.NewCustomRingEd25519Circuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func asCustomRingEd25519(a *testAssignment, authorization ed25519Authorization) frontend.Circuit {
	return &customring.CustomRingEd25519Circuit{
		CachedInputs: a.CachedInputs,
		Public: customring.CustomRingEd25519Public{
			Nullifiers:                   a.InputNullifiers(),
			OutputHashes:                 a.OutputHashes(),
			TreeSlots:                    a.TreeSlots,
			OutputTreeID:                 a.OutputTreeID,
			PrivateTxHash:                a.PrivateTxHash,
			Ed25519MessageHashLow:        authorization.low,
			Ed25519MessageHashHigh:       authorization.high,
			DefaultEd25519OwnerPkHash:    defaultEd25519OwnerPkHash(a, authorization.pkHash),
			ExternalDataHash:             a.ExternalDataHash,
			PublicAssets:                 a.PublicAssets,
			PublicAmounts:                a.PublicAmounts,
			RingProgramID:                a.RingProgramID,
			InputFlags:                   a.InputFlags,
			SignerPkHashes:               a.TransactionSignerPkHashes(),
			PublishedOutputOwnerPkHashes: a.PublishedOutputOwnerPkHashes(),
			PublicInputHash:              a.PublicInputHash,
		},
		Private: customring.CustomRingEd25519Private{
			Inputs:              a.coreInputs(),
			InputOwnerPkHashes:  a.InputOwnerPkHashes(),
			Outputs:             a.outputUtxos(),
			OutputOwnerPkHashes: a.OutputOwnerPkHashes(),
			OutputNullifierPks:  a.outputNullifierPks(),
			BlindingSeed:        a.BlindingSeed,
			Ed25519PublicKey:    ed25519Bytes32(authorization.pub),
			Ed25519Signature:    ed25519Bytes64(authorization.sig),
		},
	}
}

func rewriteInputAsEd25519(
	t testing.TB,
	assignment *testAssignment,
	inputIndex int,
	ownerPrivateKey ed25519.PrivateKey,
) {
	t.Helper()
	rewriteInputAsEd25519WithIdentity(t, assignment, inputIndex, spptest.Ed25519OwnerPkHash(t, ownerPrivateKey))
}

// rewriteInputAsEd25519WithIdentity marks the input as Ed25519-owned (zero owner
// tag) and derives its UTXO owner from an explicit identity, so a test can
// supply a wrongly derived identity the circuit's owner must not reproduce.
func rewriteInputAsEd25519WithIdentity(
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
		t.Fatalf("Ed25519 owner hash: %v", err)
	}
	assignment.Inputs[inputIndex].Utxo.Owner = owner
	assignment.Inputs[inputIndex].OwnerPkHash = spptest.Fe(0)
	rebuildAfterOwnerChange(t, assignment)
}

func authorizeEd25519(
	t testing.TB,
	assignment *testAssignment,
	publicKeyPrivate ed25519.PrivateKey,
	signingPrivate ed25519.PrivateKey,
) ed25519Authorization {
	t.Helper()
	digest := ed25519SigningDigest(assignment)
	low := new(big.Int).SetBytes(digest[16:])
	high := new(big.Int).SetBytes(digest[:16])
	var sig [64]byte
	copy(sig[:], ed25519.Sign(signingPrivate, digest[:]))
	ownerPkHash := spptest.Ed25519OwnerPkHash(t, publicKeyPrivate)
	authorization := ed25519Authorization{
		pub:    spptest.Ed25519PublicKeyBytes(publicKeyPrivate),
		sig:    sig,
		low:    low,
		high:   high,
		pkHash: ownerPkHash,
	}
	refreshCustomRingEd25519PublicInputHash(t, assignment, digest, ownerPkHash)
	return authorization
}

// ed25519SigningDigest is the 32-byte message SPP has the owner sign:
// SHA-256(private_tx_hash || external_data_hash).
func ed25519SigningDigest(assignment *testAssignment) [32]byte {
	var message [64]byte
	spptest.AsBigInt(assignment.PrivateTxHash).FillBytes(message[:32])
	spptest.AsBigInt(assignment.ExternalDataHash).FillBytes(message[32:])
	return sha256.Sum256(message[:])
}

func ed25519Bytes32(b [32]byte) [32]frontend.Variable {
	var out [32]frontend.Variable
	for i, v := range b {
		out[i] = v
	}
	return out
}

func ed25519Bytes64(b [64]byte) [64]frontend.Variable {
	var out [64]frontend.Variable
	for i, v := range b {
		out[i] = v
	}
	return out
}

func refreshCustomRingEd25519PublicInputHash(
	t testing.TB,
	assignment *testAssignment,
	messageDigest [32]byte,
	ed25519PkHash *big.Int,
) {
	t.Helper()
	refreshCustomRingEd25519PublicInputHashWithOwner(
		t,
		assignment,
		messageDigest,
		defaultEd25519OwnerPkHash(assignment, ed25519PkHash),
	)
}

// refreshCustomRingEd25519PublicInputHashWithOwner recomputes the public-input
// hash with an explicit value for the published default Ed25519 owner field, so a
// test can claim a publication the circuit must refuse.
func refreshCustomRingEd25519PublicInputHashWithOwner(
	t testing.TB,
	assignment *testAssignment,
	messageDigest [32]byte,
	publishedEd25519Owner *big.Int,
) {
	t.Helper()
	messageHash, err := protocol.HashBytes(messageDigest[:])
	if err != nil {
		t.Fatalf("Ed25519 message hash: %v", err)
	}
	// The Ed25519 rail inserts the signed message hash and the published default
	// owner right after private_tx_hash; every other element is the shared
	// preimage.
	inputs := protocol.PublicInputs{
		Nullifiers:                 spptest.ToBigInts(assignment.InputNullifiers()),
		OutputUtxoHashes:           spptest.ToBigInts(assignment.OutputHashes()),
		PrivateTxHash:              spptest.AsBigInt(assignment.PrivateTxHash),
		PreimageAfterPrivateTxHash: []*big.Int{messageHash, publishedEd25519Owner},
		ExternalDataHash:           spptest.AsBigInt(assignment.ExternalDataHash),
		RingProgramID:              spptest.AsBigInt(assignment.RingProgramID),
		SignerPkHashes:             spptest.ToBigInts(assignment.TransactionSignerPkHashes()),
		InputFlags:                 spptest.AsBigInt(assignment.InputFlags),
		BindOutputOwnerTags:        true,
		OutputOwnerPkHashes:        spptest.ToBigInts(assignment.PublishedOutputOwnerPkHashes()),
	}
	for i := 0; i < NPublicSlots; i++ {
		inputs.PublicAssets[i] = spptest.AsBigInt(assignment.PublicAssets[i])
		inputs.PublicAmounts[i] = spptest.AsBigInt(assignment.PublicAmounts[i])
	}
	assignment.PublicInputHash = testPublicInputHash(
		t, inputs, assignment.TreeSlots, assignment.OutputTreeID, assignment.CachedInputs,
	)
}

// defaultEd25519OwnerPkHash mirrors the public field the circuit constrains: the Ed25519
// identity while a spent default-ring UTXO belongs to it, zero otherwise.
// Address slots do not publish the identity.
func defaultEd25519OwnerPkHash(assignment *testAssignment, ed25519PkHash *big.Int) *big.Int {
	for _, input := range assignment.Inputs {
		domain := spptest.AsBigInt(input.Utxo.Domain).Int64()
		if domain == UtxoDomain &&
			spptest.AsBigInt(input.OwnerPkHash).Sign() == 0 &&
			spptest.AsBigInt(input.Utxo.RingProgramID).Sign() == 0 {
			return new(big.Int).Set(ed25519PkHash)
		}
	}
	return big.NewInt(0)
}

func TestCustomRingEd25519Solves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingEd25519PublicInputHashBindsEveryField(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	var messageDigest [32]byte
	authorization.high.FillBytes(messageDigest[:16])
	authorization.low.FillBytes(messageDigest[16:])
	refreshHash := func() {
		refreshCustomRingEd25519PublicInputHash(t, assignment, messageDigest, authorization.pkHash)
	}
	extraMutations := []publicInputHashMutation{
		{name: "ed25519_message_hash_low", run: func() {
			changed := messageDigest
			changed[31] ^= 1
			refreshCustomRingEd25519PublicInputHash(t, assignment, changed, authorization.pkHash)
		}},
		{name: "ed25519_message_hash_high", run: func() {
			changed := messageDigest
			changed[0] ^= 1
			refreshCustomRingEd25519PublicInputHash(t, assignment, changed, authorization.pkHash)
		}},
		{name: "default_ed25519_owner_pk_hash", run: func() {
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
		func() frontend.Circuit { return asCustomRingEd25519(assignment, authorization) },
		refreshHash,
		publicInputHashBindingOptions{
			includeRingProgramID:       true,
			includeOutputOwnerPkHashes: true,
			signerWidth:                len(assignment.SignerPkHashes),
			extraMutations:             extraMutations,
		},
	)
}

func TestCustomRingEd25519KeepsRingOnlyOwnerPrivate(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rebuildAfterOwnerChange(t, assignment)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingEd25519AcceptsMixedOwners(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// rewriteOutputAsEd25519 makes output slot outputIndex owned by the shared Ed25519
// key. A default-ring output then publishes the Ed25519 identity through the
// published owner vector; a ring output keeps it private.
func rewriteOutputAsEd25519(
	t testing.TB,
	assignment *testAssignment,
	outputIndex int,
	ownerPrivateKey ed25519.PrivateKey,
) {
	t.Helper()
	ownerPkHash := spptest.Ed25519OwnerPkHash(t, ownerPrivateKey)
	nullifierPk := spptest.AsBigInt(assignment.Outputs[outputIndex].NullifierPk)
	owner, err := protocol.OwnerHash(ownerPkHash, nullifierPk)
	if err != nil {
		t.Fatalf("Ed25519 owner hash: %v", err)
	}
	assignment.Outputs[outputIndex].Utxo.Owner = owner
	assignment.Outputs[outputIndex].OwnerPkHash = ownerPkHash
	rebuildAfterOwnerChange(t, assignment)
}

// A ring Ed25519 input is an anonymous spend. Spending a default-ring Ed25519 UTXO
// in the same proof would publish the shared key next to the ring nullifier.
func TestCustomRingEd25519RejectsRingSpendWithDefaultEd25519Input(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	rewriteInputAsEd25519(t, assignment, 1, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rebuildAfterOwnerChange(t, assignment)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// Two default-ring Ed25519 inputs publish the owner once, which is the allowed
// confidential default-ring spend.
func TestCustomRingEd25519AcceptsTwoDefaultEd25519Inputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	rewriteInputAsEd25519(t, assignment, 1, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// A default-ring output owned by the shared key publishes the identity, so it
// cannot sit next to a ring Ed25519 spend.
func TestCustomRingEd25519RejectsRingSpendPublishingEd25519Output(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rewriteOutputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// A ring Ed25519 spend may pay the shared key inside the ring: the output owner
// stays private, so nothing links the spend to the identity.
func TestCustomRingEd25519AcceptsRingSpendToRingEd25519Output(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rewriteOutputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// Moving a default-ring Ed25519 UTXO into the ring publishes the depositor, not a
// ring spender, so the mixed transaction stays allowed.
func TestCustomRingEd25519AcceptsDefaultEd25519DepositIntoRing(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rewriteOutputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// hashEd25519Key hashes the owner's 32-byte public key prefixed with the
// given tag bytes. It builds the identities the circuit must refuse: no tag is
// the untagged hash_bytes_32(pk), and protocol.P256OwnerTag is the retired
// P256 tag over the same bytes.
func hashEd25519Key(t testing.TB, ownerPrivateKey ed25519.PrivateKey, tag ...byte) *big.Int {
	t.Helper()
	pk := spptest.Ed25519PublicKeyBytes(ownerPrivateKey)
	identity, err := protocol.HashBytes(append(tag, pk[:]...))
	if err != nil {
		t.Fatalf("Ed25519 key hash: %v", err)
	}
	return identity
}

func TestCustomRingEd25519RejectsUntaggedOwnerIdentity(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519WithIdentity(t, assignment, 0, hashEd25519Key(t, owner))
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingEd25519RejectsP256TaggedOwnerIdentity(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519WithIdentity(t, assignment, 0, hashEd25519Key(t, owner, protocol.P256OwnerTag))
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// ed25519DummyOutputAssignment pads a Ed25519 transaction with a dummy output whose
// published tag is tag. The single input is owned by owner; inRing places the
// spend in the policy ring, which keeps the shared identity private.
func ed25519DummyOutputAssignment(
	t testing.TB,
	shape protocol.Shape,
	owner ed25519.PrivateKey,
	inRing bool,
	tag frontend.Variable,
) (*testAssignment, ed25519Authorization) {
	t.Helper()
	assignment := dummyOutputAssignment(t, shape)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	if inRing {
		assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
		rebuildAfterOwnerChange(t, assignment)
	}
	tagDummyOutput(t, assignment, tag)
	authorization := authorizeEd25519(t, assignment, owner, owner)
	return assignment, authorization
}

// A ring Ed25519 spend keeps the shared identity private, so a dummy output may
// not publish it: the copy would deanonymize the spender. Both the dummy-tag
// rule and AssertDefaultEd25519Owner reject this; the unit test in
// owner_tags_test.go isolates the dummy-tag rule.
func TestCustomRingEd25519RejectsDummyOutputNamingRingSpender(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	owner := spptest.FixedEd25519Key(t, 11)

	// Control: the same ring spend solves with an anonymous dummy.
	assignment, authorization := ed25519DummyOutputAssignment(t, shape, owner, true, 0)
	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)

	assignment, authorization = ed25519DummyOutputAssignment(t, shape, owner, true, spptest.Ed25519OwnerPkHash(t, owner))
	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// A default-ring Ed25519 input already publishes the shared identity, so a dummy
// may repeat it.
func TestCustomRingEd25519AcceptsDummyOutputNamingPublishedEd25519Owner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	owner := spptest.FixedEd25519Key(t, 11)
	assignment, authorization := ed25519DummyOutputAssignment(t, shape, owner, false, spptest.Ed25519OwnerPkHash(t, owner))

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// makeEd25519AddressSlot turns input idx into an address slot owned by the shared
// Ed25519 owner. The zero owner tag selects the Ed25519 key; the owner hash is over
// its pk field.
func makeEd25519AddressSlot(
	t testing.TB,
	assignment *testAssignment,
	idx int,
	owner ed25519.PrivateKey,
	seed *big.Int,
) {
	t.Helper()
	setAddressSlot(t, &assignment.Inputs[idx], spptest.Ed25519OwnerPkHash(t, owner), spptest.Fe(0), seed)
}

// ed25519AddressAssignment spends a Ed25519 UTXO in input 0 and creates a Ed25519
// address in input 1, both owned by the same key. inRing places the spend in
// the policy ring; the address sits in the default ring.
func ed25519AddressAssignment(t testing.TB, inRing bool) (*testAssignment, ed25519Authorization) {
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
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	if inRing {
		assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
		rebuildAfterOwnerChange(t, assignment)
	}
	makeEd25519AddressSlot(t, assignment, 1, owner, spptest.Fe(0xABCDEF))
	finalizeAddressAssignment(t, assignment, true, false)
	return assignment, authorizeEd25519(t, assignment, owner, owner)
}

// ed25519AddressOnlyAssignment creates a single Ed25519 address and spends nothing.
func ed25519AddressOnlyAssignment(t testing.TB) (*testAssignment, ed25519Authorization) {
	t.Helper()
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAsset := protocol.SolAsset()
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(0))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(0))),
	)
	owner := spptest.FixedEd25519Key(t, 11)
	makeEd25519AddressSlot(t, assignment, 0, owner, spptest.Fe(0xABCDEF))
	finalizeAddressAssignment(t, assignment, true, false)
	return assignment, authorizeEd25519(t, assignment, owner, owner)
}

// claimingPublishedEd25519Owner rebuilds the witness with the shared identity
// forced into the public default-owner field and its public-input hash.
func claimingPublishedEd25519Owner(
	t testing.TB,
	assignment *testAssignment,
	authorization ed25519Authorization,
) frontend.Circuit {
	t.Helper()
	var digest [32]byte
	authorization.high.FillBytes(digest[:16])
	authorization.low.FillBytes(digest[16:])
	refreshCustomRingEd25519PublicInputHashWithOwner(t, assignment, digest, authorization.pkHash)
	circuit := asCustomRingEd25519(assignment, authorization).(*customring.CustomRingEd25519Circuit)
	circuit.Public.DefaultEd25519OwnerPkHash = authorization.pkHash
	return circuit
}

// A ring Ed25519 spender may create an address in the same proof. The address
// has ring id 0, but it spends nothing, so it neither counts as a
// default-ring input nor publishes the shared identity.
func TestCustomRingEd25519AcceptsAddressDuringRingSpend(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewCustomRingEd25519Circuit(Shape(protocol.Shape{NInputs: 2, NOutputs: 2}))
	assignment, authorization := ed25519AddressAssignment(t, true)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingFailed(
		circuit,
		claimingPublishedEd25519Owner(t, assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// A default-ring Ed25519 spend publishes the identity regardless of an address
// slot beside it.
func TestCustomRingEd25519PublishesOwnerForDefaultSpendWithAddress(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewCustomRingEd25519Circuit(Shape(protocol.Shape{NInputs: 2, NOutputs: 2}))
	assignment, authorization := ed25519AddressAssignment(t, false)
	if defaultEd25519OwnerPkHash(assignment, authorization.pkHash).Sign() == 0 {
		t.Fatal("default-ring Ed25519 spend must publish the shared owner")
	}

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// Creating an address alone spends nothing and publishes nothing: the public
// default-owner field must be zero even though the address sits in ring 0.
func TestCustomRingEd25519AddressOnlyKeepsOwnerPrivate(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewCustomRingEd25519Circuit(Shape(protocol.Shape{NInputs: 1, NOutputs: 2}))
	assignment, authorization := ed25519AddressOnlyAssignment(t)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingFailed(
		circuit,
		claimingPublishedEd25519Owner(t, assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// The payer is excluded from dummy markers on this rail as well.
func TestCustomRingEd25519RejectsDummyOutputPayerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	owner := spptest.FixedEd25519Key(t, 11)
	assignment, authorization := ed25519DummyOutputAssignment(t, shape, owner, false, testPayerPkHash())

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingEd25519RejectsBadSignature(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	wrongSigner := spptest.FixedEd25519Key(t, 12)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, wrongSigner)

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingEd25519RejectsBadMessageHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)
	authorization.low = new(big.Int).Add(authorization.low, big.NewInt(1))

	var changedDigest [32]byte
	authorization.high.FillBytes(changedDigest[:16])
	authorization.low.FillBytes(changedDigest[16:])
	refreshCustomRingEd25519PublicInputHash(t, assignment, changedDigest, authorization.pkHash)

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingEd25519RejectsSignatureForDifferentExternalData(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	original := authorizeEd25519(t, assignment, owner, owner)
	assignment.ExternalDataHash = spptest.Fe(301)
	reauthorized := authorizeEd25519(t, assignment, owner, owner)
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(circuit, asCustomRingEd25519(assignment, reauthorized), test.WithCurves(ecc.BN254))
	reauthorized.sig = original.sig
	assert.SolvingFailed(circuit, asCustomRingEd25519(assignment, reauthorized), test.WithCurves(ecc.BN254))
}

func TestCustomRingEd25519RejectsOwnerKeyMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	otherOwner := spptest.FixedEd25519Key(t, 12)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, otherOwner, otherOwner)

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

func TestCustomRingEd25519RejectsUndecodablePublicKey(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)
	authorization.pub = ed25519OffCurveKey(t)

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// ed25519OffCurveKey returns a 32-byte encoding whose y has no matching x, so
// it decodes to no point; a PDA is exactly such an address.
func ed25519OffCurveKey(t testing.TB) [32]byte {
	t.Helper()
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	d := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), p))
	d.Mod(d, p)
	for y := int64(2); y < 1000; y++ {
		yy := new(big.Int).Mul(big.NewInt(y), big.NewInt(y))
		u := new(big.Int).Sub(yy, big.NewInt(1))
		v := new(big.Int).Add(new(big.Int).Mul(d, yy), big.NewInt(1))
		x2 := new(big.Int).Mul(u, new(big.Int).ModInverse(v.Mod(v, p), p))
		x2.Mod(x2, p)
		if x2.Sign() != 0 && big.Jacobi(x2, p) == -1 {
			var key [32]byte
			big.NewInt(y).FillBytes(key[:])
			for i, j := 0, len(key)-1; i < j; i, j = i+1, j-1 {
				key[i], key[j] = key[j], key[i]
			}
			return key
		}
	}
	t.Fatal("no off-curve y below 1000")
	return [32]byte{}
}

// withSharedIdentityAsSigner places the shared Ed25519 identity in the public
// signer vector at slot, as SPP does when the same wallet also signs the
// Solana transaction (slot 0 is the fee payer).
func withSharedIdentityAsSigner(
	t testing.TB,
	assignment *testAssignment,
	owner ed25519.PrivateKey,
	slot int,
) {
	t.Helper()
	signers := append([]frontend.Variable(nil), assignment.TransactionSignerPkHashes()...)
	signers[slot] = spptest.Ed25519OwnerPkHash(t, owner)
	assignment.SignerPkHashes = signers
}

// The shared Ed25519 identity is the Solana identity of the key, so the
// runtime can publish it as a signer. During a ring spend that would name the
// anonymous spender, whether as fee payer or as an owner co-signer.
func TestCustomRingEd25519RejectsRingSpendWithSharedIdentityAsSigner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	owner := spptest.FixedEd25519Key(t, 11)
	for _, slot := range []int{0, 1} {
		assignment := buildCircuitAssignment(t, shape)
		rewriteInputAsEd25519(t, assignment, 0, owner)
		assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
		rebuildAfterOwnerChange(t, assignment)
		withSharedIdentityAsSigner(t, assignment, owner, slot)
		authorization := authorizeEd25519(t, assignment, owner, owner)

		assert.SolvingFailed(
			circuit,
			asCustomRingEd25519(assignment, authorization),
			test.WithCurves(ecc.BN254),
		)
	}
}

// A default-ring Ed25519 spend publishes the identity anyway, so the same key
// may also pay the fee.
func TestCustomRingEd25519AcceptsDefaultSpendWithSharedIdentityAsPayer(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	withSharedIdentityAsSigner(t, assignment, owner, 0)
	authorization := authorizeEd25519(t, assignment, owner, owner)

	assert.SolvingSucceeded(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// The circuit signs the SPP digest bytes in their natural order: a signature
// over the byte-reversed digest must not verify.
func TestCustomRingEd25519RejectsSignatureOverReversedDigest(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedEd25519Key(t, 11)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	authorization := authorizeEd25519(t, assignment, owner, owner)
	digest := ed25519SigningDigest(assignment)
	for i, j := 0, len(digest)-1; i < j; i, j = i+1, j-1 {
		digest[i], digest[j] = digest[j], digest[i]
	}
	copy(authorization.sig[:], ed25519.Sign(owner, digest[:]))

	assert.SolvingFailed(
		circuit,
		asCustomRingEd25519(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}
