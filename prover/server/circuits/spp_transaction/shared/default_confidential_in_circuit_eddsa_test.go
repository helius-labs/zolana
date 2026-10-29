package shared_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"testing/cryptotest"

	defaultring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/default"
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

const confidentialEddsaFixture = "../../../prover/transfer_eddsa/testdata/confidential-eddsa-2x8.json"

// confidentialEddsaSigners is the owner count every transfer_confidential_eddsa
// key pins; the proof system in prover/transfer_eddsa uses the same value.
const confidentialEddsaSigners = 1

var confidentialEddsaSystems = map[Shape]constraint.ConstraintSystem{}

func compileConfidentialEddsa(t testing.TB, shape protocol.Shape) constraint.ConstraintSystem {
	t.Helper()
	if ccs, ok := confidentialEddsaSystems[Shape(shape)]; ok {
		return ccs
	}
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		MustNewDefaultRingConfidentialInCircuitEddsaCircuit(Shape(shape)),
		frontend.WithCompressThreshold(300),
	)
	if err != nil {
		t.Fatal(err)
	}
	confidentialEddsaSystems[Shape(shape)] = ccs
	return ccs
}

func MustNewDefaultRingConfidentialInCircuitEddsaCircuit(shape Shape) *defaultring.DefaultRingConfidentialInCircuitEddsaCircuit {
	circuit, err := defaultring.NewDefaultRingConfidentialInCircuitEddsaCircuit(shape, confidentialEddsaSigners)
	if err != nil {
		panic(err)
	}
	return circuit
}

func asDefaultRingConfidentialInCircuitEddsa(
	a *testAssignment,
	authorization eddsaAuthorization,
) *defaultring.DefaultRingConfidentialInCircuitEddsaCircuit {
	c := &defaultring.DefaultRingConfidentialInCircuitEddsaCircuit{
		CachedInputs: a.CachedInputs,
		NSigners:     confidentialEddsaSigners,
		Public: defaultring.DefaultRingConfidentialInCircuitEddsaPublic{
			Nullifiers:          a.InputNullifiers(),
			OutputHashes:        a.OutputHashes(),
			TreeSlots:           a.TreeSlots,
			OutputTreeID:        a.OutputTreeID,
			PrivateTxHash:       a.PrivateTxHash,
			MessageHashLow:      authorization.low,
			MessageHashHigh:     authorization.high,
			ExternalDataHash:    a.ExternalDataHash,
			PublicAssets:        a.PublicAssets,
			PublicAmounts:       a.PublicAmounts,
			InputFlags:          a.InputFlags,
			SignerPkHashes:      a.TransactionSignerPkHashes(),
			OutputOwnerPkHashes: a.OutputOwnerPkHashes(),
			PublicInputHash:     a.PublicInputHash,
		},
		Private: defaultring.DefaultRingConfidentialInCircuitEddsaPrivate{
			Inputs:             a.coreInputs(),
			InputOwnerPkHashes: a.InputOwnerPkHashes(),
			Outputs:            a.outputUtxos(),
			OutputNullifierPks: a.outputNullifierPks(),
			BlindingSeed:       a.BlindingSeed,
			OwnerPublicKeys:    make([][32]frontend.Variable, confidentialEddsaSigners),
			OwnerSignatures:    make([][64]frontend.Variable, confidentialEddsaSigners),
		},
	}
	for i, b := range authorization.key {
		c.Private.OwnerPublicKeys[0][i] = b
	}
	for i, b := range authorization.signature {
		c.Private.OwnerSignatures[0][i] = b
	}
	return c
}

// rewriteInputAsEddsaOwner hands input inputIndex to the in-circuit owner: its
// UTXO owner derives from the owner's Solana identity, which stays the input's
// owner tag because the identity is published, not hidden.
func rewriteInputAsEddsaOwner(
	t testing.TB,
	assignment *testAssignment,
	inputIndex int,
	owner ed25519.PrivateKey,
) {
	t.Helper()
	identity := hiddenOwnerIdentity(t, publicKeyBytes(owner))
	nullifierPk := spptest.MustNullifierPk(
		t,
		spptest.AsBigInt(assignment.Inputs[inputIndex].NullifierSecret),
	)
	ownerHash, err := protocol.OwnerHash(identity, nullifierPk)
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Inputs[inputIndex].Utxo.Owner = ownerHash
	assignment.Inputs[inputIndex].OwnerPkHash = identity
	rebuildAfterOwnerChange(t, assignment)
}

// withoutOwnerSigners empties the Solana owner-signer vector: only the fee
// payer signs the transaction, and it is never in the vector.
func withoutOwnerSigners(assignment *testAssignment) {
	assignment.SignerPkHashes = asFrontendVariables(zeroFields(assignment.Shape.SignerWidth()))
}

// authorizeConfidentialEddsa presents the key of publicKeyPrivate with
// signingPrivate's signature over the transact digest and refreshes the
// rail's public-input hash.
func authorizeConfidentialEddsa(
	t testing.TB,
	assignment *testAssignment,
	publicKeyPrivate ed25519.PrivateKey,
	signingPrivate ed25519.PrivateKey,
) eddsaAuthorization {
	t.Helper()
	key := publicKeyBytes(publicKeyPrivate)
	digest := eddsaDigest(assignment)
	authorization := eddsaAuthorization{
		key:    key,
		low:    new(big.Int).SetBytes(digest[16:]),
		high:   new(big.Int).SetBytes(digest[:16]),
		pkHash: hiddenOwnerIdentity(t, key),
	}
	copy(authorization.signature[:], ed25519.Sign(signingPrivate, digest[:]))
	refreshConfidentialEddsaPublicInputHash(t, assignment, digest, authorization.pkHash)
	return authorization
}

// refreshConfidentialEddsaPublicInputHash recomputes the public-input hash:
// the default confidential preimage with the signed message hash and the
// chain of the verified owner identities after private_tx_hash.
func refreshConfidentialEddsaPublicInputHash(
	t testing.TB,
	assignment *testAssignment,
	messageDigest [32]byte,
	ownerIdentity *big.Int,
) {
	t.Helper()
	messageHash, err := protocol.HashBytes(messageDigest[:])
	if err != nil {
		t.Fatalf("message hash: %v", err)
	}
	ownerChain, err := protocol.RightHashChain4([]*big.Int{ownerIdentity})
	if err != nil {
		t.Fatalf("owner chain: %v", err)
	}
	assignment.RingProgramID = spptest.Fe(0)
	inputs := protocol.PublicInputs{
		Nullifiers:                 spptest.ToBigInts(assignment.InputNullifiers()),
		OutputUtxoHashes:           spptest.ToBigInts(assignment.OutputHashes()),
		PrivateTxHash:              spptest.AsBigInt(assignment.PrivateTxHash),
		PreimageAfterPrivateTxHash: []*big.Int{messageHash, ownerChain},
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

// relayedConfidentialEddsaAssignment spends every input of a default-ring
// transaction as the in-circuit owner with no Solana owner signer.
func relayedConfidentialEddsaAssignment(
	t testing.TB,
	shape protocol.Shape,
	owner ed25519.PrivateKey,
) *testAssignment {
	t.Helper()
	assignment := buildDefaultRingConfidentialEddsaAssignment(t, shape)
	for i := range assignment.Inputs {
		rewriteInputAsEddsaOwner(t, assignment, i, owner)
	}
	withoutOwnerSigners(assignment)
	return assignment
}

// The owner authorizes the spend in-circuit; no owner signs the transaction.
func TestDefaultRingConfidentialInCircuitEddsaSolves(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	owner := hiddenOwnerKey(11)
	assignment := relayedConfidentialEddsaAssignment(t, shape, owner)
	authorization := authorizeConfidentialEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileConfidentialEddsa(t, shape), asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), true)
}

// The smallest key shape proves and verifies end to end with one BSB22
// commitment over private wires, the only commitment the on-chain verifier
// accepts.
func TestDefaultRingConfidentialInCircuitEddsaProves(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 8}
	ccs := compileConfidentialEddsa(t, shape)
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	if len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 {
		t.Fatalf("want one BSB22 commitment over private wires, got %+v", commitments)
	}

	owner := hiddenOwnerKey(0x91)
	a := relayedConfidentialEddsaAssignment(t, shape, owner)
	assignment := asDefaultRingConfidentialInCircuitEddsa(a, authorizeConfidentialEddsa(t, a, owner, owner))
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

func TestDefaultRingConfidentialInCircuitEddsaPublicInputHashBindsEveryField(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultRingConfidentialInCircuitEddsaCircuit(Shape(shape))
	owner := hiddenOwnerKey(11)
	assignment := relayedConfidentialEddsaAssignment(t, shape, owner)
	authorization := authorizeConfidentialEddsa(t, assignment, owner, owner)

	messageDigest := authorization.digest()
	refreshHash := func() {
		refreshConfidentialEddsaPublicInputHash(t, assignment, messageDigest, authorization.pkHash)
	}
	extraMutations := []publicInputHashMutation{
		{name: "message_hash_low", run: func() {
			changed := messageDigest
			changed[31] ^= 1
			refreshConfidentialEddsaPublicInputHash(t, assignment, changed, authorization.pkHash)
		}},
		{name: "message_hash_high", run: func() {
			changed := messageDigest
			changed[0] ^= 1
			refreshConfidentialEddsaPublicInputHash(t, assignment, changed, authorization.pkHash)
		}},
	}
	assertPublicInputHashBindsEveryField(
		t,
		circuit,
		assignment,
		func() frontend.Circuit { return asDefaultRingConfidentialInCircuitEddsa(assignment, authorization) },
		refreshHash,
		publicInputHashBindingOptions{
			includeOutputOwnerPkHashes: true,
			signerWidth:                len(assignment.SignerPkHashes),
			extraMutations:             extraMutations,
		},
	)
}

// One input belongs to the in-circuit owner and the other to a Solana owner
// signer: both authorizations hold in one proof.
func TestDefaultRingConfidentialInCircuitEddsaAcceptsMixedOwners(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	assignment := buildDefaultRingConfidentialEddsaAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsEddsaOwner(t, assignment, 0, owner)
	authorization := authorizeConfidentialEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileConfidentialEddsa(t, shape), asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), true)
}

// The Solana signer vector is unchanged by the in-circuit owner: an input of a
// Solana owner outside the vector stays unauthorized.
func TestDefaultRingConfidentialInCircuitEddsaRejectsAnInputOwnerOutsideTheSignerVector(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	assignment := buildDefaultRingConfidentialEddsaAssignment(t, shape)
	owner := hiddenOwnerKey(11)
	rewriteInputAsEddsaOwner(t, assignment, 0, owner)
	withoutOwnerSigners(assignment)
	authorization := authorizeConfidentialEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileConfidentialEddsa(t, shape), asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), false)
}

// A verified key that owns no input authorizes nothing it does not own: the
// input of another Ed25519 owner stays unauthorized.
func TestDefaultRingConfidentialInCircuitEddsaRejectsOwnerKeyMismatch(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	owner := hiddenOwnerKey(11)
	otherOwner := hiddenOwnerKey(12)
	assignment := relayedConfidentialEddsaAssignment(t, shape, owner)
	authorization := authorizeConfidentialEddsa(t, assignment, otherOwner, otherOwner)

	checkCachedWitness(t, compileConfidentialEddsa(t, shape), asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), false)
}

func TestDefaultRingConfidentialInCircuitEddsaRejectsBadSignature(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	owner := hiddenOwnerKey(11)
	wrongSigner := hiddenOwnerKey(12)
	assignment := relayedConfidentialEddsaAssignment(t, shape, owner)
	authorization := authorizeConfidentialEddsa(t, assignment, owner, wrongSigner)

	checkCachedWitness(t, compileConfidentialEddsa(t, shape), asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), false)
}

func TestDefaultRingConfidentialInCircuitEddsaRejectsBadMessageHash(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	owner := hiddenOwnerKey(11)
	assignment := relayedConfidentialEddsaAssignment(t, shape, owner)
	authorization := authorizeConfidentialEddsa(t, assignment, owner, owner)
	authorization.low = new(big.Int).Add(authorization.low, big.NewInt(1))
	refreshConfidentialEddsaPublicInputHash(t, assignment, authorization.digest(), authorization.pkHash)

	checkCachedWitness(t, compileConfidentialEddsa(t, shape), asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), false)
}

// The signature binds the external data: a signature over other external
// data does not authorize this transaction.
func TestDefaultRingConfidentialInCircuitEddsaRejectsSignatureForDifferentExternalData(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	ccs := compileConfidentialEddsa(t, shape)
	owner := hiddenOwnerKey(11)
	assignment := relayedConfidentialEddsaAssignment(t, shape, owner)
	original := authorizeConfidentialEddsa(t, assignment, owner, owner)
	assignment.ExternalDataHash = spptest.Fe(301)
	reauthorized := authorizeConfidentialEddsa(t, assignment, owner, owner)
	checkCachedWitness(t, ccs, asDefaultRingConfidentialInCircuitEddsa(assignment, reauthorized), true)
	reauthorized.signature = original.signature
	checkCachedWitness(t, ccs, asDefaultRingConfidentialInCircuitEddsa(assignment, reauthorized), false)
}

// The published owner identity is the one the signature verifies: claiming
// another identity in the public inputs fails even with a valid signature.
func TestDefaultRingConfidentialInCircuitEddsaRejectsClaimedOwnerIdentity(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	owner := hiddenOwnerKey(11)
	assignment := relayedConfidentialEddsaAssignment(t, shape, owner)
	authorization := authorizeConfidentialEddsa(t, assignment, owner, owner)
	claimed := hiddenOwnerIdentity(t, publicKeyBytes(hiddenOwnerKey(12)))
	refreshConfidentialEddsaPublicInputHash(t, assignment, authorization.digest(), claimed)

	checkCachedWitness(t, compileConfidentialEddsa(t, shape), asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), false)
}

// The verified owner is a transaction participant: a data-carrying output
// and a dummy output may name it.
func TestDefaultRingConfidentialInCircuitEddsaOwnerIsAParticipant(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	ccs := compileConfidentialEddsa(t, shape)
	owner := hiddenOwnerKey(11)
	identity := hiddenOwnerIdentity(t, publicKeyBytes(owner))

	assignment := dummyOutputAssignment(t, shape)
	rewriteInputAsEddsaOwner(t, assignment, 0, owner)
	withoutOwnerSigners(assignment)
	tagDummyOutput(t, assignment, identity)
	authorization := authorizeConfidentialEddsa(t, assignment, owner, owner)
	checkCachedWitness(t, ccs, asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), true)

	assignment = relayedConfidentialEddsaAssignment(t, shape, owner)
	assignment.Outputs[0].Utxo.DataHash = spptest.Fe(0x99)
	rewriteOutputAsHiddenOwner(t, assignment, 0, owner)
	authorization = authorizeConfidentialEddsa(t, assignment, owner, owner)
	checkCachedWitness(t, ccs, asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), true)
}

// A data-carrying output owned by a key that neither signed the transaction
// nor the digest does not solve.
func TestDefaultRingConfidentialInCircuitEddsaRejectsDataHashOnThirdPartyOutput(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	owner := hiddenOwnerKey(11)
	assignment := relayedConfidentialEddsaAssignment(t, shape, owner)
	assignment.Outputs[0].Utxo.DataHash = spptest.Fe(0x99)
	rewriteOutputAsHiddenOwner(t, assignment, 0, hiddenOwnerKey(12))
	authorization := authorizeConfidentialEddsa(t, assignment, owner, owner)

	checkCachedWitness(t, compileConfidentialEddsa(t, shape), asDefaultRingConfidentialInCircuitEddsa(assignment, authorization), false)
}

// TestDefaultRingConfidentialInCircuitEddsaRequestFixture pins the 2x8 request
// the program test recomputes the public input hash from. Rewrite it with
//
//	UPDATE_REQUEST_FIXTURE=1 go test ./circuits/spp_transaction/shared -run TestDefaultRingConfidentialInCircuitEddsaRequestFixture
func TestDefaultRingConfidentialInCircuitEddsaRequestFixture(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 0)
	shape := protocol.Shape{NInputs: 2, NOutputs: 8}
	owner := hiddenOwnerKey(0x91)
	a := relayedConfidentialEddsaAssignment(t, shape, owner)
	circuit := asDefaultRingConfidentialInCircuitEddsa(a, authorizeConfidentialEddsa(t, a, owner, owner))
	data, err := json.Marshal(confidentialEddsaRequestParameters(circuit))
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	var decoded transfer.ConfidentialEddsaTransferParameters
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
	checkCachedWitness(t, compileConfidentialEddsa(t, shape), witness, true)
	if os.Getenv("UPDATE_REQUEST_FIXTURE") != "" {
		if err := os.WriteFile(confidentialEddsaFixture, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	committed, err := os.ReadFile(confidentialEddsaFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, data) {
		t.Fatal("the committed confidential EdDSA request is stale; rewrite it with UPDATE_REQUEST_FIXTURE=1")
	}
}

// confidentialEddsaRequestParameters inverts
// ConfidentialEddsaTransferParameters.CreateWitness.
func confidentialEddsaRequestParameters(
	c *defaultring.DefaultRingConfidentialInCircuitEddsaCircuit,
) *transfer.ConfidentialEddsaTransferParameters {
	value := spptest.AsBigInt
	values := spptest.ToBigInts
	p := &transfer.ConfidentialEddsaTransferParameters{
		TransferParameters: transfer.TransferParameters{
			NInputs:                      uint32(len(c.Private.Inputs)),
			NOutputs:                     uint32(len(c.Private.Outputs)),
			OutputTreeID:                 value(c.Public.OutputTreeID),
			ExternalDataHash:             value(c.Public.ExternalDataHash),
			PrivateTxHash:                value(c.Public.PrivateTxHash),
			BlindingSeed:                 value(c.Private.BlindingSeed),
			PublicAssets:                 values(c.Public.PublicAssets[:]),
			PublicAmounts:                values(c.Public.PublicAmounts[:]),
			RingProgramID:                big.NewInt(0),
			SignerPkHashes:               values(c.Public.SignerPkHashes),
			InputFlags:                   value(c.Public.InputFlags),
			PublishedOutputOwnerPkHashes: values(c.Public.OutputOwnerPkHashes),
			Cache: transfer.CacheSelectionParams{
				TreeID:        value(c.CachedInputs.TreeID),
				ReadHashChain: value(c.CachedInputs.ReadHashChain),
				ReadHashes:    values(c.CachedInputs.ReadHashes),
				IsCached:      values(c.CachedInputs.IsCached),
				ReadIndex:     values(c.CachedInputs.ReadIndex),
			},
			Variant:         transfer.ConfidentialVariant,
			PublicInputHash: value(c.Public.PublicInputHash),
		},
		MessageHashLow:  value(c.Public.MessageHashLow),
		MessageHashHigh: value(c.Public.MessageHashHigh),
	}
	for i := range p.OwnerPublicKey {
		p.OwnerPublicKey[i] = c.Private.OwnerPublicKeys[0][i].(byte)
	}
	for i := range p.OwnerSignature {
		p.OwnerSignature[i] = c.Private.OwnerSignatures[0][i].(byte)
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
			OwnerPkHash: value(c.Public.OutputOwnerPkHashes[i]),
			NullifierPk: value(c.Private.OutputNullifierPks[i]),
		})
	}
	return p
}
