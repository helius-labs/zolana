package shared_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"testing"
	"testing/cryptotest"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const eddsaRingFixture = "../../../prover/transfer_eddsa/testdata/eddsa-ring-2x2.json"

var eddsaRingSystems = map[Shape]constraint.ConstraintSystem{}

func compileEddsaRing(t testing.TB, shape protocol.Shape) constraint.ConstraintSystem {
	t.Helper()
	if ccs, ok := eddsaRingSystems[Shape(shape)]; ok {
		return ccs
	}
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		MustNewCustomRingAnonymousEddsaCircuit(Shape(shape)),
		frontend.WithCompressThreshold(300),
	)
	if err != nil {
		t.Fatal(err)
	}
	eddsaRingSystems[Shape(shape)] = ccs
	return ccs
}

type eddsaAuthorization struct {
	key       [32]byte
	signature [64]byte
	low       *big.Int
	high      *big.Int
	pkHash    *big.Int
}

func (a eddsaAuthorization) digest() [32]byte {
	var digest [32]byte
	a.high.FillBytes(digest[:16])
	a.low.FillBytes(digest[16:])
	return digest
}

func MustNewCustomRingAnonymousEddsaCircuit(shape Shape) *customring.CustomRingAnonymousEddsaCircuit {
	circuit, err := customring.NewCustomRingAnonymousEddsaCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func asCustomRingAnonymousEddsa(a *testAssignment, authorization eddsaAuthorization) *customring.CustomRingAnonymousEddsaCircuit {
	c := &customring.CustomRingAnonymousEddsaCircuit{
		CachedInputs: a.CachedInputs,
		Public: customring.CustomRingAnonymousEddsaPublic{
			Nullifiers:                   a.InputNullifiers(),
			OutputHashes:                 a.OutputHashes(),
			TreeSlots:                    a.TreeSlots,
			OutputTreeID:                 a.OutputTreeID,
			PrivateTxHash:                a.PrivateTxHash,
			MessageHashLow:               authorization.low,
			MessageHashHigh:              authorization.high,
			DefaultOwnerPkHash:           defaultOwnerPkHash(a, authorization.pkHash),
			ExternalDataHash:             a.ExternalDataHash,
			PublicAssets:                 a.PublicAssets,
			PublicAmounts:                a.PublicAmounts,
			RingProgramID:                a.RingProgramID,
			InputFlags:                   a.InputFlags,
			SignerPkHashes:               a.TransactionSignerPkHashes(),
			PublishedOutputOwnerPkHashes: a.PublishedOutputOwnerPkHashes(),
			PublicInputHash:              a.PublicInputHash,
		},
		Private: customring.CustomRingAnonymousEddsaPrivate{
			Inputs:              a.coreInputs(),
			InputOwnerPkHashes:  a.InputOwnerPkHashes(),
			Outputs:             a.outputUtxos(),
			OutputOwnerPkHashes: a.OutputOwnerPkHashes(),
			OutputNullifierPks:  a.outputNullifierPks(),
			BlindingSeed:        a.BlindingSeed,
		},
	}
	for i, b := range authorization.key {
		c.Private.OwnerPublicKey[i] = b
	}
	for i, b := range authorization.signature {
		c.Private.OwnerSignature[i] = b
	}
	return c
}

func hiddenOwnerKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func publicKeyBytes(key ed25519.PrivateKey) [32]byte {
	return [32]byte(key.Public().(ed25519.PublicKey))
}

func hiddenOwnerIdentity(t testing.TB, key [32]byte) *big.Int {
	t.Helper()
	identity, err := protocol.SolanaPkField(key)
	return spptest.MustHash(t, identity, err)
}

func rewriteInputAsHiddenOwner(
	t testing.TB,
	assignment *testAssignment,
	inputIndex int,
	owner ed25519.PrivateKey,
) {
	t.Helper()
	rewriteInputAsHiddenOwnerWithIdentity(t, assignment, inputIndex, hiddenOwnerIdentity(t, publicKeyBytes(owner)))
}

// rewriteInputAsHiddenOwnerWithIdentity marks the input as hidden-owner (zero
// owner tag) and derives its UTXO owner from an explicit identity, so a test
// can supply a wrongly derived identity the circuit's owner must not reproduce.
func rewriteInputAsHiddenOwnerWithIdentity(
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
		t.Fatalf("hidden owner hash: %v", err)
	}
	assignment.Inputs[inputIndex].Utxo.Owner = owner
	assignment.Inputs[inputIndex].OwnerPkHash = spptest.Fe(0)
	rebuildAfterOwnerChange(t, assignment)
}

func eddsaDigest(a *testAssignment) [32]byte {
	var message [64]byte
	spptest.AsBigInt(a.PrivateTxHash).FillBytes(message[:32])
	spptest.AsBigInt(a.ExternalDataHash).FillBytes(message[32:])
	return sha256.Sum256(message[:])
}

func authorizeEddsa(
	t testing.TB,
	assignment *testAssignment,
	publicKeyPrivate ed25519.PrivateKey,
	signingPrivate ed25519.PrivateKey,
) eddsaAuthorization {
	t.Helper()
	return authorizeEddsaKey(t, assignment, publicKeyBytes(publicKeyPrivate), signingPrivate)
}

// authorizeEddsaKey presents key with signingPrivate's signature, the two may differ.
func authorizeEddsaKey(
	t testing.TB,
	assignment *testAssignment,
	key [32]byte,
	signingPrivate ed25519.PrivateKey,
) eddsaAuthorization {
	t.Helper()
	digest := eddsaDigest(assignment)
	authorization := eddsaAuthorization{
		key:    key,
		low:    new(big.Int).SetBytes(digest[16:]),
		high:   new(big.Int).SetBytes(digest[:16]),
		pkHash: hiddenOwnerIdentity(t, key),
	}
	copy(authorization.signature[:], ed25519.Sign(signingPrivate, digest[:]))
	refreshCustomRingAnonymousEddsaPublicInputHash(t, assignment, digest, authorization.pkHash)
	return authorization
}

func refreshCustomRingAnonymousEddsaPublicInputHash(
	t testing.TB,
	assignment *testAssignment,
	messageDigest [32]byte,
	hiddenOwnerPkHash *big.Int,
) {
	t.Helper()
	refreshCustomRingAnonymousEddsaPublicInputHashWithOwner(
		t,
		assignment,
		messageDigest,
		defaultOwnerPkHash(assignment, hiddenOwnerPkHash),
	)
}

// refreshCustomRingAnonymousEddsaPublicInputHashWithOwner recomputes the
// public-input hash with an explicit value for the published default owner
// field, so a test can claim a publication the circuit must refuse.
func refreshCustomRingAnonymousEddsaPublicInputHashWithOwner(
	t testing.TB,
	assignment *testAssignment,
	messageDigest [32]byte,
	publishedOwner *big.Int,
) {
	t.Helper()
	messageHash, err := protocol.HashBytes(messageDigest[:])
	if err != nil {
		t.Fatalf("message hash: %v", err)
	}
	// The anonymous rail inserts the signed message hash and the published
	// default owner right after private_tx_hash; every other element is the
	// shared preimage.
	inputs := protocol.PublicInputs{
		Nullifiers:                 spptest.ToBigInts(assignment.InputNullifiers()),
		OutputUtxoHashes:           spptest.ToBigInts(assignment.OutputHashes()),
		PrivateTxHash:              spptest.AsBigInt(assignment.PrivateTxHash),
		PreimageAfterPrivateTxHash: []*big.Int{messageHash, publishedOwner},
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

// defaultOwnerPkHash mirrors the public field the circuit constrains: the
// hidden identity while a spent default-ring UTXO belongs to it, zero
// otherwise. Address slots do not publish the identity.
func defaultOwnerPkHash(assignment *testAssignment, hiddenOwnerPkHash *big.Int) *big.Int {
	for _, input := range assignment.Inputs {
		domain := spptest.AsBigInt(input.Utxo.Domain).Int64()
		if domain == UtxoDomain &&
			spptest.AsBigInt(input.OwnerPkHash).Sign() == 0 &&
			spptest.AsBigInt(input.Utxo.RingProgramID).Sign() == 0 {
			return new(big.Int).Set(hiddenOwnerPkHash)
		}
	}
	return big.NewInt(0)
}

func TestCustomRingAnonymousEddsaSolves(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	authorization := authorizeEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), true)
}

// The shape proves and verifies end to end with one BSB22 commitment over
// private wires, the only commitment the on-chain verifier accepts.
func TestCustomRingAnonymousEddsaProves(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	ccs := compileEddsaRing(t, shape)
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	if len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 {
		t.Fatalf("want one BSB22 commitment over private wires, got %+v", commitments)
	}

	_, a, owner := honestEddsaRing(t)
	assignment := asCustomRingAnonymousEddsa(a, authorizeEddsa(t, a, owner, owner))
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal(err)
	}
	assignment.Public.PublicInputHash = new(big.Int).Add(spptest.AsBigInt(assignment.Public.PublicInputHash), big.NewInt(1))
	changed, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, changed); err == nil {
		t.Fatal("proof accepted a different public input hash")
	}
}

func TestCustomRingAnonymousEddsaPublicInputHashBindsEveryField(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingAnonymousEddsaCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	authorization := authorizeEddsa(t, assignment, owner, owner)

	messageDigest := authorization.digest()
	refreshHash := func() {
		refreshCustomRingAnonymousEddsaPublicInputHash(t, assignment, messageDigest, authorization.pkHash)
	}
	extraMutations := []publicInputHashMutation{
		{name: "message_hash_low", run: func() {
			changed := messageDigest
			changed[31] ^= 1
			refreshCustomRingAnonymousEddsaPublicInputHash(t, assignment, changed, authorization.pkHash)
		}},
		{name: "message_hash_high", run: func() {
			changed := messageDigest
			changed[0] ^= 1
			refreshCustomRingAnonymousEddsaPublicInputHash(t, assignment, changed, authorization.pkHash)
		}},
		{name: "default_owner_pk_hash", run: func() {
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
		func() frontend.Circuit { return asCustomRingAnonymousEddsa(assignment, authorization) },
		refreshHash,
		publicInputHashBindingOptions{
			includeRingProgramID:       true,
			includeOutputOwnerPkHashes: true,
			signerWidth:                len(assignment.SignerPkHashes),
			extraMutations:             extraMutations,
		},
	)
}

func TestCustomRingAnonymousEddsaKeepsRingOnlyOwnerPrivate(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rebuildAfterOwnerChange(t, assignment)
	authorization := authorizeEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), true)
}

func TestCustomRingAnonymousEddsaAcceptsMixedOwners(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	authorization := authorizeEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), true)
}

// rewriteOutputAsHiddenOwner makes output slot outputIndex owned by the hidden
// owner. A default-ring output then publishes the hidden identity through the
// published owner vector; a ring output keeps it private.
func rewriteOutputAsHiddenOwner(
	t testing.TB,
	assignment *testAssignment,
	outputIndex int,
	owner ed25519.PrivateKey,
) {
	t.Helper()
	ownerPkHash := hiddenOwnerIdentity(t, publicKeyBytes(owner))
	nullifierPk := spptest.AsBigInt(assignment.Outputs[outputIndex].NullifierPk)
	ownerHash, err := protocol.OwnerHash(ownerPkHash, nullifierPk)
	if err != nil {
		t.Fatalf("hidden owner hash: %v", err)
	}
	assignment.Outputs[outputIndex].Utxo.Owner = ownerHash
	assignment.Outputs[outputIndex].OwnerPkHash = ownerPkHash
	rebuildAfterOwnerChange(t, assignment)
}

// A ring hidden-owner input is an anonymous spend. Spending a default-ring
// hidden-owner UTXO in the same proof would publish the hidden key next to the
// ring nullifier.
func TestCustomRingAnonymousEddsaRejectsRingSpendWithDefaultHiddenInput(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	rewriteInputAsHiddenOwner(t, assignment, 1, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rebuildAfterOwnerChange(t, assignment)
	authorization := authorizeEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), false)
}

// Two default-ring hidden-owner inputs publish the owner once, which is the
// allowed confidential default-ring spend.
func TestCustomRingAnonymousEddsaAcceptsTwoDefaultHiddenInputs(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	rewriteInputAsHiddenOwner(t, assignment, 1, owner)
	authorization := authorizeEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), true)
}

// A default-ring output owned by the hidden key publishes the identity, so it
// cannot sit next to a ring hidden-owner spend.
func TestCustomRingAnonymousEddsaRejectsRingSpendPublishingHiddenOwnerOutput(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rewriteOutputAsHiddenOwner(t, assignment, 0, owner)
	authorization := authorizeEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), false)
}

// A ring hidden-owner spend may pay the hidden key inside the ring: the output
// owner stays private, so nothing links the spend to the identity.
func TestCustomRingAnonymousEddsaAcceptsRingSpendToRingHiddenOwnerOutput(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rewriteOutputAsHiddenOwner(t, assignment, 0, owner)
	authorization := authorizeEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), true)
}

// Moving a default-ring hidden-owner UTXO into the ring publishes the
// depositor, not a ring spender, so the mixed transaction stays allowed.
func TestCustomRingAnonymousEddsaAcceptsDefaultHiddenOwnerDepositIntoRing(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	rewriteOutputAsHiddenOwner(t, assignment, 0, owner)
	authorization := authorizeEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), true)
}

// The untagged hash_bytes_32 over the key is not the owner identity the
// circuit derives from the verified key.
func TestCustomRingAnonymousEddsaRejectsUntaggedOwnerIdentity(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	key := publicKeyBytes(owner)
	untagged, err := protocol.HashBytes(key[:])
	rewriteInputAsHiddenOwnerWithIdentity(t, assignment, 0, spptest.MustHash(t, untagged, err))
	authorization := authorizeEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), false)
}

// anonymousDummyOutputAssignment pads an anonymous transaction with a dummy
// output whose published tag is tag. The single input is owned by owner;
// inRing places the spend in the policy ring, which keeps the hidden identity
// private.
func anonymousDummyOutputAssignment(
	t testing.TB,
	shape protocol.Shape,
	owner ed25519.PrivateKey,
	inRing bool,
	tag frontend.Variable,
) (*testAssignment, eddsaAuthorization) {
	t.Helper()
	assignment := dummyOutputAssignment(t, shape)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	if inRing {
		assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
		rebuildAfterOwnerChange(t, assignment)
	}
	tagDummyOutput(t, assignment, tag)
	authorization := authorizeEddsa(t, assignment, owner, owner)
	return assignment, authorization
}

// A ring hidden-owner spend keeps the hidden identity private, so a dummy
// output may not publish it: the copy would deanonymize the spender. Both the
// dummy-tag rule and AssertDefaultHiddenOwner reject this; the unit test in
// owner_tags_test.go isolates the dummy-tag rule.
func TestCustomRingAnonymousEddsaRejectsDummyOutputNamingRingSpender(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	ccs := compileEddsaRing(t, shape)
	owner := hiddenOwnerKey(11)

	// Control: the same ring spend solves with an anonymous dummy.
	assignment, authorization := anonymousDummyOutputAssignment(t, shape, owner, true, 0)
	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(assignment, authorization), true)

	assignment, authorization = anonymousDummyOutputAssignment(t, shape, owner, true, hiddenOwnerIdentity(t, publicKeyBytes(owner)))
	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(assignment, authorization), false)
}

// A default-ring hidden-owner input already publishes the hidden identity, so
// a dummy may repeat it.
func TestCustomRingAnonymousEddsaAcceptsDummyOutputNamingPublishedOwner(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	owner := hiddenOwnerKey(11)
	assignment, authorization := anonymousDummyOutputAssignment(t, shape, owner, false, hiddenOwnerIdentity(t, publicKeyBytes(owner)))

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), true)
}

// makeHiddenOwnerAddressSlot turns input idx into an address slot owned by the
// hidden owner. The zero owner tag selects the hidden key; the owner hash is
// over its identity.
func makeHiddenOwnerAddressSlot(
	t testing.TB,
	assignment *testAssignment,
	idx int,
	owner ed25519.PrivateKey,
	seed *big.Int,
) {
	t.Helper()
	setAddressSlot(t, &assignment.Inputs[idx], hiddenOwnerIdentity(t, publicKeyBytes(owner)), spptest.Fe(0), seed)
}

// hiddenOwnerAddressAssignment spends a hidden-owner UTXO in input 0 and
// creates a hidden-owner address in input 1, both owned by the same key.
// inRing places the spend in the policy ring; the address sits in the default
// ring.
func hiddenOwnerAddressAssignment(t testing.TB, inRing bool) (*testAssignment, eddsaAuthorization) {
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
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	if inRing {
		assignment.Inputs[0].Utxo.RingProgramID = assignment.RingProgramID
		rebuildAfterOwnerChange(t, assignment)
	}
	makeHiddenOwnerAddressSlot(t, assignment, 1, owner, spptest.Fe(0xABCDEF))
	finalizeAddressAssignment(t, assignment, false)
	return assignment, authorizeEddsa(t, assignment, owner, owner)
}

// hiddenOwnerAddressOnlyAssignment creates a single hidden-owner address and
// spends nothing.
func hiddenOwnerAddressOnlyAssignment(t testing.TB) (*testAssignment, eddsaAuthorization) {
	t.Helper()
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAsset := protocol.SolAsset()
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(0))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(0))),
	)
	owner := hiddenOwnerKey(11)
	makeHiddenOwnerAddressSlot(t, assignment, 0, owner, spptest.Fe(0xABCDEF))
	finalizeAddressAssignment(t, assignment, false)
	return assignment, authorizeEddsa(t, assignment, owner, owner)
}

// claimingPublishedOwner rebuilds the witness with the hidden identity forced
// into the public default-owner field and its public-input hash.
func claimingPublishedOwner(
	t testing.TB,
	assignment *testAssignment,
	authorization eddsaAuthorization,
) frontend.Circuit {
	t.Helper()
	refreshCustomRingAnonymousEddsaPublicInputHashWithOwner(t, assignment, authorization.digest(), authorization.pkHash)
	circuit := asCustomRingAnonymousEddsa(assignment, authorization)
	circuit.Public.DefaultOwnerPkHash = authorization.pkHash
	return circuit
}

// A ring hidden-owner spender may create an address in the same proof. The
// address has ring id 0, but it spends nothing, so it neither counts as a
// default-ring input nor publishes the hidden identity.
func TestCustomRingAnonymousEddsaAcceptsAddressDuringRingSpend(t *testing.T) {
	ccs := compileEddsaRing(t, protocol.Shape{NInputs: 2, NOutputs: 2})
	assignment, authorization := hiddenOwnerAddressAssignment(t, true)

	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(assignment, authorization), true)
	checkCachedWitness(t, ccs, claimingPublishedOwner(t, assignment, authorization), false)
}

// A default-ring hidden-owner spend publishes the identity regardless of an
// address slot beside it.
func TestCustomRingAnonymousEddsaPublishesOwnerForDefaultSpendWithAddress(t *testing.T) {
	assignment, authorization := hiddenOwnerAddressAssignment(t, false)
	if defaultOwnerPkHash(assignment, authorization.pkHash).Sign() == 0 {
		t.Fatal("default-ring hidden-owner spend must publish the hidden owner")
	}

	checkCachedWitness(
		t,
		compileEddsaRing(t, protocol.Shape{NInputs: 2, NOutputs: 2}),
		asCustomRingAnonymousEddsa(assignment, authorization),
		true,
	)
}

// Creating an address alone spends nothing and publishes nothing: the public
// default-owner field must be zero even though the address sits in ring 0.
func TestCustomRingAnonymousEddsaAddressOnlyKeepsOwnerPrivate(t *testing.T) {
	ccs := compileEddsaRing(t, protocol.Shape{NInputs: 1, NOutputs: 2})
	assignment, authorization := hiddenOwnerAddressOnlyAssignment(t)

	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(assignment, authorization), true)
	checkCachedWitness(t, ccs, claimingPublishedOwner(t, assignment, authorization), false)
}

// The payer is excluded from dummy markers on this rail as well.
func TestCustomRingAnonymousEddsaRejectsDummyOutputPayerTag(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	owner := hiddenOwnerKey(11)
	assignment, authorization := anonymousDummyOutputAssignment(t, shape, owner, false, testPayerPkHash())

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), false)
}

func TestCustomRingAnonymousEddsaRejectsBadSignature(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	wrongSigner := hiddenOwnerKey(12)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	authorization := authorizeEddsa(t, assignment, owner, wrongSigner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), false)
}

func TestCustomRingAnonymousEddsaRejectsBadMessageHash(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	authorization := authorizeEddsa(t, assignment, owner, owner)
	authorization.low = new(big.Int).Add(authorization.low, big.NewInt(1))
	refreshCustomRingAnonymousEddsaPublicInputHash(t, assignment, authorization.digest(), authorization.pkHash)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), false)
}

func TestCustomRingAnonymousEddsaRejectsSignatureForDifferentExternalData(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	ccs := compileEddsaRing(t, shape)
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	original := authorizeEddsa(t, assignment, owner, owner)
	assignment.ExternalDataHash = spptest.Fe(301)
	reauthorized := authorizeEddsa(t, assignment, owner, owner)
	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(assignment, reauthorized), true)
	reauthorized.signature = original.signature
	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(assignment, reauthorized), false)
}

func TestCustomRingAnonymousEddsaRejectsOwnerKeyMismatch(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	otherOwner := hiddenOwnerKey(12)
	rewriteInputAsHiddenOwner(t, assignment, 0, owner)
	authorization := authorizeEddsa(t, assignment, otherOwner, otherOwner)

	checkCachedWitness(t, compileEddsaRing(t, shape), asCustomRingAnonymousEddsa(assignment, authorization), false)
}

// Every note stays in the ring and the payer is the only public signer.
func eddsaRingAssignment(t testing.TB, shape protocol.Shape, identity *big.Int) *testAssignment {
	t.Helper()
	a := buildCircuitAssignment(t, shape)
	for i := range a.Inputs {
		a.Inputs[i].Utxo.RingProgramID = a.RingProgramID
	}
	for i := range a.Outputs {
		a.Outputs[i].Utxo.RingProgramID = a.RingProgramID
	}
	a.SignerPkHashes = asFrontendVariables(zeroFields(shape.SignerWidth()))
	a.SignerPkHashes[0] = testPayerPkHash()
	for i := range a.Inputs {
		rewriteInputAsHiddenOwnerWithIdentity(t, a, i, identity)
	}
	return a
}

func honestEddsaRing(t testing.TB) (constraint.ConstraintSystem, *testAssignment, ed25519.PrivateKey) {
	t.Helper()
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	owner := hiddenOwnerKey(0x91)
	a := eddsaRingAssignment(t, shape, hiddenOwnerIdentity(t, publicKeyBytes(owner)))
	return compileEddsaRing(t, shape), a, owner
}

// The hidden identity shares the Solana identity hash, so it must differ from
// every public signer.
func TestCustomRingAnonymousEddsaRejectsHiddenOwnerAsPublicSigner(t *testing.T) {
	ccs, _, owner := honestEddsaRing(t)
	identity := hiddenOwnerIdentity(t, publicKeyBytes(owner))
	for _, slot := range []int{0, 1} {
		_, a, _ := honestEddsaRing(t)
		a.SignerPkHashes[slot] = identity
		checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(a, authorizeEddsa(t, a, owner, owner)), false)
	}
}

func TestCustomRingAnonymousEddsaRequiresHiddenInput(t *testing.T) {
	ccs, a, owner := honestEddsaRing(t)
	signer := testSolanaPkField(t)
	nullifierPk := spptest.MustNullifierPk(t, spptest.AsBigInt(a.Inputs[1].NullifierSecret))
	a.Inputs[1].Utxo.Owner = spptest.MustOwnerHash(t, signer, nullifierPk)
	a.Inputs[1].OwnerPkHash = signer
	a.SignerPkHashes[1] = signer
	rebuildAfterOwnerChange(t, a)
	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(a, authorizeEddsa(t, a, owner, owner)), true)

	a.Inputs[0].Utxo.Owner = a.Inputs[1].Utxo.Owner
	a.Inputs[0].OwnerPkHash = signer
	rebuildAfterOwnerChange(t, a)
	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(a, authorizeEddsa(t, a, owner, owner)), false)
}

// A key outside the prime subgroup or with a non-canonical encoding carries a
// signature the Go standard library accepts. The rail must still refuse it.
func TestCustomRingAnonymousEddsaRejectsTorsionAndNonCanonicalKeys(t *testing.T) {
	owner := hiddenOwnerKey(0x91)
	h := sha512.Sum512(owner.Seed())
	secret := clampedScalar(h[:32])
	if edEncode(edMul(secret, edBase())) != publicKeyBytes(owner) {
		t.Fatal("test curve arithmetic disagrees with crypto/ed25519")
	}
	torsion := edDecode(t, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	identity := edEncode(edPoint{big.NewInt(0), big.NewInt(1)})
	if edEncode(edMul(big.NewInt(8), torsion)) != identity || edEncode(edMul(big.NewInt(4), torsion)) == identity {
		t.Fatal("the torsion point does not have order 8")
	}
	cases := map[string]struct {
		key    [32]byte
		secret *big.Int
		order  int64
	}{
		"mixed_torsion": {edEncode(edAdd(edMul(secret, edBase()), torsion)), secret, 8},
		// y = p encodes the order-4 point (sqrt(-1), 0) without reducing y.
		"non_canonical_small_order": {nonCanonicalOrderFourKey(), big.NewInt(0), 4},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			shape := protocol.Shape{NInputs: 2, NOutputs: 2}
			ccs := compileEddsaRing(t, shape)
			a := eddsaRingAssignment(t, shape, hiddenOwnerIdentity(t, tc.key))
			auth := authorizeEddsaKey(t, a, tc.key, owner)
			digest := auth.digest()
			auth.signature = lenientSignature(tc.key, tc.secret, tc.order, digest[:])
			if !ed25519.Verify(tc.key[:], digest[:], auth.signature[:]) {
				t.Fatal("crypto/ed25519 rejects the forged signature, so the case proves nothing")
			}
			checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(a, auth), false)
		})
	}
}

// TestCustomRingAnonymousEddsaRequestFixture pins the 2x2 request the program test
// recomputes the public input hash from. Rewrite it with
//
//	UPDATE_REQUEST_FIXTURE=1 go test ./circuits/spp_transaction/shared -run TestCustomRingAnonymousEddsaRequestFixture
func TestCustomRingAnonymousEddsaRequestFixture(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 0)
	_, a, owner := honestEddsaRing(t)
	circuit := asCustomRingAnonymousEddsa(a, authorizeEddsa(t, a, owner, owner))
	data, err := json.Marshal(eddsaRequestParameters(circuit))
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	var decoded transfer.AnonymousEddsaTransferParameters
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.ValidateShape(); err != nil {
		t.Fatal(err)
	}
	witness, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	checkCachedWitness(t, compileEddsaRing(t, protocol.Shape{NInputs: 2, NOutputs: 2}), witness, true)
	if os.Getenv("UPDATE_REQUEST_FIXTURE") != "" {
		if err := os.WriteFile(eddsaRingFixture, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	committed, err := os.ReadFile(eddsaRingFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, data) {
		t.Fatal("the committed EdDSA ring request is stale; rewrite it with UPDATE_REQUEST_FIXTURE=1")
	}
}

// eddsaRequestParameters inverts AnonymousEddsaTransferParameters.CreateWitness.
func eddsaRequestParameters(c *customring.CustomRingAnonymousEddsaCircuit) *transfer.AnonymousEddsaTransferParameters {
	value := spptest.AsBigInt
	values := spptest.ToBigInts
	p := &transfer.AnonymousEddsaTransferParameters{
		NInputs:                      uint32(len(c.Private.Inputs)),
		NOutputs:                     uint32(len(c.Private.Outputs)),
		OutputTreeID:                 value(c.Public.OutputTreeID),
		ExternalDataHash:             value(c.Public.ExternalDataHash),
		PrivateTxHash:                value(c.Public.PrivateTxHash),
		BlindingSeed:                 value(c.Private.BlindingSeed),
		MessageHashLow:               value(c.Public.MessageHashLow),
		MessageHashHigh:              value(c.Public.MessageHashHigh),
		DefaultOwnerPkHash:           value(c.Public.DefaultOwnerPkHash),
		PublicAssets:                 values(c.Public.PublicAssets[:]),
		PublicAmounts:                values(c.Public.PublicAmounts[:]),
		RingProgramID:                value(c.Public.RingProgramID),
		SignerPkHashes:               values(c.Public.SignerPkHashes),
		InputFlags:                   value(c.Public.InputFlags),
		PublishedOutputOwnerPkHashes: values(c.Public.PublishedOutputOwnerPkHashes),
		Cache: transfer.CacheSelectionParams{
			TreeID:        value(c.CachedInputs.TreeID),
			ReadHashChain: value(c.CachedInputs.ReadHashChain),
			ReadHashes:    values(c.CachedInputs.ReadHashes),
			IsCached:      values(c.CachedInputs.IsCached),
			ReadIndex:     values(c.CachedInputs.ReadIndex),
		},
		PublicInputHash: value(c.Public.PublicInputHash),
	}
	for i := range p.OwnerPublicKey {
		p.OwnerPublicKey[i] = c.Private.OwnerPublicKey[i].(byte)
	}
	for i := range p.OwnerSignature {
		p.OwnerSignature[i] = c.Private.OwnerSignature[i].(byte)
	}
	for _, slot := range c.Public.TreeSlots {
		p.TreeSlots = append(p.TreeSlots, common.TreeSlotParams{
			ID:            value(slot.ID),
			UtxoRoot:      value(slot.UtxoRoot),
			NullifierRoot: value(slot.NullifierRoot),
		})
	}
	for i, in := range c.Private.Inputs {
		p.Inputs = append(p.Inputs, transfer.InputParams{
			Utxo:                     utxoParams(in.Utxo),
			StatePathElements:        values(in.StatePathElements),
			StatePathIndex:           value(in.StatePathIndex),
			NullifierLowValue:        value(in.NullifierLowValue),
			NullifierNextValue:       value(in.NullifierNextValue),
			NullifierLowPathElements: values(in.NullifierLowPathElements),
			NullifierLowPathIndex:    value(in.NullifierLowPathIndex),
			TreeSlot:                 value(in.TreeSlot),
			Nullifier:                value(c.Public.Nullifiers[i]),
			OwnerPkHash:              value(c.Private.InputOwnerPkHashes[i]),
			NullifierSecret:          value(in.NullifierSecret),
		})
	}
	for i, out := range c.Private.Outputs {
		p.Outputs = append(p.Outputs, transfer.OutputParams{
			Utxo:        utxoParams(out),
			Hash:        value(c.Public.OutputHashes[i]),
			OwnerPkHash: value(c.Private.OutputOwnerPkHashes[i]),
			NullifierPk: value(c.Private.OutputNullifierPks[i]),
		})
	}
	return p
}

// Affine edwards25519 arithmetic, only to forge keys crypto/ed25519 cannot make.
var (
	edP     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edL, _  = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	edD     = edDiv(big.NewInt(-121665), big.NewInt(121666))
	edSqrtM = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP)
)

type edPoint struct{ x, y *big.Int }

func edDiv(a, b *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(new(big.Int).Mod(b, edP), edP)
	return new(big.Int).Mod(new(big.Int).Mul(a, inv), edP)
}

func edAdd(a, b edPoint) edPoint {
	xy := new(big.Int).Mul(new(big.Int).Mul(a.x, b.x), new(big.Int).Mul(a.y, b.y))
	dxy := new(big.Int).Mul(edD, xy)
	x := new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(a.y, b.x))
	y := new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x))
	return edPoint{
		edDiv(x, new(big.Int).Add(big.NewInt(1), dxy)),
		edDiv(y, new(big.Int).Sub(big.NewInt(1), dxy)),
	}
}

func edMul(k *big.Int, p edPoint) edPoint {
	out := edPoint{big.NewInt(0), big.NewInt(1)}
	for i := k.BitLen() - 1; i >= 0; i-- {
		out = edAdd(out, out)
		if k.Bit(i) == 1 {
			out = edAdd(out, p)
		}
	}
	return out
}

func edBase() edPoint {
	y := edDiv(big.NewInt(4), big.NewInt(5))
	return edPoint{edRecoverX(y, 0), y}
}

func edRecoverX(y *big.Int, sign uint) *big.Int {
	y2 := new(big.Int).Mul(y, y)
	x2 := edDiv(new(big.Int).Sub(y2, big.NewInt(1)), new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1)))
	x := new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(edP, big.NewInt(3)), 3), edP)
	if new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(x, x), x2), edP).Sign() != 0 {
		x.Mod(x.Mul(x, edSqrtM), edP)
	}
	if x.Bit(0) != sign {
		x.Sub(edP, x)
	}
	return x
}

func edEncode(p edPoint) [32]byte {
	var out [32]byte
	p.y.FillBytes(out[:])
	slices.Reverse(out[:])
	out[31] |= byte(p.x.Bit(0)) << 7
	return out
}

func edDecode(t testing.TB, encoded string) edPoint {
	t.Helper()
	le, err := hex.DecodeString(encoded)
	if err != nil || len(le) != 32 {
		t.Fatal("bad point encoding")
	}
	sign := uint(le[31] >> 7)
	le[31] &= 0x7f
	slices.Reverse(le)
	y := new(big.Int).SetBytes(le)
	return edPoint{edRecoverX(y, sign), y}
}

func clampedScalar(b []byte) *big.Int {
	le := slices.Clone(b)
	le[0] &= 248
	le[31] &= 127
	le[31] |= 64
	slices.Reverse(le)
	return new(big.Int).SetBytes(le)
}

func nonCanonicalOrderFourKey() [32]byte {
	var key [32]byte
	edP.FillBytes(key[:])
	slices.Reverse(key[:])
	key[31] |= 0x80
	return key
}

// lenientSignature signs with secret for key = secret*B + T, where T has the
// given small order, by grinding a nonce whose challenge annihilates T.
func lenientSignature(key [32]byte, secret *big.Int, order int64, message []byte) [64]byte {
	for nonce := int64(1); ; nonce++ {
		r := big.NewInt(nonce)
		commitment := edEncode(edMul(r, edBase()))
		digest := sha512.Sum512(slices.Concat(commitment[:], key[:], message))
		slices.Reverse(digest[:])
		challenge := new(big.Int).Mod(new(big.Int).SetBytes(digest[:]), edL)
		if new(big.Int).Mod(challenge, big.NewInt(order)).Sign() != 0 {
			continue
		}
		s := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(challenge, secret)), edL)
		var signature [64]byte
		copy(signature[:32], commitment[:])
		s.FillBytes(signature[32:])
		slices.Reverse(signature[32:])
		return signature
	}
}
