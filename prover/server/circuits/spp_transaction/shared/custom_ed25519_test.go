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
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa_only"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const ed25519RingFixture = "../../../prover/transfer_eddsa_only/testdata/ed25519-ring-2x2.json"

var ed25519RingSystems = map[Shape]constraint.ConstraintSystem{}

func compileEd25519Ring(t testing.TB, shape protocol.Shape) constraint.ConstraintSystem {
	t.Helper()
	if ccs, ok := ed25519RingSystems[Shape(shape)]; ok {
		return ccs
	}
	circuit, err := customring.NewCustomRingEd25519Circuit(Shape(shape))
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	ed25519RingSystems[Shape(shape)] = ccs
	return ccs
}

type ed25519Authorization struct {
	key       [32]byte
	signature [64]byte
	digest    [32]byte
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

// hideInput makes input i a ring note of the hidden owner, with tag zero and an
// owner hash over identity. Callers rebuild the assignment afterwards.
func hideInput(t testing.TB, a *testAssignment, i int, identity *big.Int) {
	t.Helper()
	nullifierPk := spptest.MustNullifierPk(t, spptest.AsBigInt(a.Inputs[i].NullifierSecret))
	a.Inputs[i].Utxo.Owner = spptest.MustOwnerHash(t, identity, nullifierPk)
	a.Inputs[i].Utxo.RingProgramID = a.RingProgramID
	a.Inputs[i].OwnerPkHash = 0
}

// ed25519RingAssignment spends ring notes of identity into ring outputs. The
// payer is the only public signer.
func ed25519RingAssignment(t testing.TB, shape protocol.Shape, identity *big.Int) *testAssignment {
	t.Helper()
	a := buildCircuitAssignment(t, shape)
	for i := range a.Inputs {
		hideInput(t, a, i, identity)
	}
	for i := range a.Outputs {
		a.Outputs[i].Utxo.RingProgramID = a.RingProgramID
	}
	a.SignerPkHashes = asFrontendVariables(zeroFields(shape.SignerWidth()))
	a.SignerPkHashes[0] = testPayerPkHash()
	rebuildAfterOwnerChange(t, a)
	return a
}

func ed25519RingDigest(a *testAssignment) [32]byte {
	var message [64]byte
	spptest.AsBigInt(a.PrivateTxHash).FillBytes(message[:32])
	spptest.AsBigInt(a.ExternalDataHash).FillBytes(message[32:])
	return sha256.Sum256(message[:])
}

// authorizeEd25519 signs the assignment's digest with signer, presents key and
// binds the public input hash with zero published output owners.
func authorizeEd25519(t testing.TB, a *testAssignment, key [32]byte, signer ed25519.PrivateKey) ed25519Authorization {
	t.Helper()
	auth := ed25519Authorization{key: key, digest: ed25519RingDigest(a)}
	copy(auth.signature[:], ed25519.Sign(signer, auth.digest[:]))
	refreshEd25519PublicInputHash(t, a, auth.digest, zeroFields(len(a.Outputs)))
	return auth
}

// refreshEd25519PublicInputHash commits the RingP256 preimage with a zero
// default owner and the given published output owners.
func refreshEd25519PublicInputHash(t testing.TB, a *testAssignment, digest [32]byte, published []*big.Int) {
	t.Helper()
	messageHash, err := protocol.HashBytes(digest[:])
	inputs := protocol.PublicInputs{
		Nullifiers:                 spptest.ToBigInts(a.InputNullifiers()),
		OutputUtxoHashes:           spptest.ToBigInts(a.OutputHashes()),
		PrivateTxHash:              spptest.AsBigInt(a.PrivateTxHash),
		PreimageAfterPrivateTxHash: []*big.Int{spptest.MustHash(t, messageHash, err), big.NewInt(0)},
		ExternalDataHash:           spptest.AsBigInt(a.ExternalDataHash),
		RingProgramID:              spptest.AsBigInt(a.RingProgramID),
		SignerPkHashes:             spptest.ToBigInts(a.TransactionSignerPkHashes()),
		InputFlags:                 spptest.AsBigInt(a.InputFlags),
		BindOutputOwnerTags:        true,
		OutputOwnerPkHashes:        published,
	}
	for i := 0; i < NPublicSlots; i++ {
		inputs.PublicAssets[i] = spptest.AsBigInt(a.PublicAssets[i])
		inputs.PublicAmounts[i] = spptest.AsBigInt(a.PublicAmounts[i])
	}
	a.PublicInputHash = testPublicInputHash(t, inputs, a.TreeSlots, a.OutputTreeID, a.CachedInputs)
}

func asCustomRingEd25519(a *testAssignment, auth ed25519Authorization) *customring.CustomRingEd25519Circuit {
	c := &customring.CustomRingEd25519Circuit{
		CachedInputs: a.CachedInputs,
		Public: customring.CustomRingEd25519Public{
			Nullifiers:       a.InputNullifiers(),
			OutputHashes:     a.OutputHashes(),
			TreeSlots:        a.TreeSlots,
			OutputTreeID:     a.OutputTreeID,
			PrivateTxHash:    a.PrivateTxHash,
			MessageHashLow:   new(big.Int).SetBytes(auth.digest[16:]),
			MessageHashHigh:  new(big.Int).SetBytes(auth.digest[:16]),
			ExternalDataHash: a.ExternalDataHash,
			PublicAssets:     a.PublicAssets,
			PublicAmounts:    a.PublicAmounts,
			RingProgramID:    a.RingProgramID,
			InputFlags:       a.InputFlags,
			SignerPkHashes:   a.TransactionSignerPkHashes(),
			PublicInputHash:  a.PublicInputHash,
		},
		Private: customring.CustomRingEd25519Private{
			Inputs:              a.coreInputs(),
			InputOwnerPkHashes:  a.InputOwnerPkHashes(),
			Outputs:             a.outputUtxos(),
			OutputOwnerPkHashes: a.OutputOwnerPkHashes(),
			OutputNullifierPks:  a.outputNullifierPks(),
			BlindingSeed:        a.BlindingSeed,
		},
	}
	for i, b := range auth.key {
		c.Private.OwnerPublicKey[i] = b
	}
	for i, b := range auth.signature {
		c.Private.OwnerSignature[i] = b
	}
	return c
}

// honestEd25519Ring is a solving 2x2 hidden-owner spend and its compiled system.
func honestEd25519Ring(t testing.TB) (constraint.ConstraintSystem, *testAssignment, ed25519.PrivateKey) {
	t.Helper()
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	owner := hiddenOwnerKey(0x91)
	a := ed25519RingAssignment(t, shape, hiddenOwnerIdentity(t, publicKeyBytes(owner)))
	return compileEd25519Ring(t, shape), a, owner
}

func TestCustomRingEd25519ProvesSupportedShapes(t *testing.T) {
	owner := hiddenOwnerKey(0x91)
	identity := hiddenOwnerIdentity(t, publicKeyBytes(owner))
	for _, shape := range protocol.RingEd25519Shapes {
		t.Run(shape.String(), func(t *testing.T) {
			ccs := compileEd25519Ring(t, shape)
			commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
			if len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 {
				t.Fatalf("want one BSB22 commitment over private wires, got %+v", commitments)
			}
			t.Logf("RingEd25519 %s: %d constraints", shape, ccs.GetNbConstraints())

			a := ed25519RingAssignment(t, shape, identity)
			assignment := asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(owner), owner))
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
		})
	}
}

func TestCustomRingEd25519RejectsWrongDigest(t *testing.T) {
	ccs, a, owner := honestEd25519Ring(t)
	auth := authorizeEd25519(t, a, publicKeyBytes(owner), owner)
	checkCachedWitness(t, ccs, asCustomRingEd25519(a, auth), true)

	t.Run("other_external_data", func(t *testing.T) {
		other := *a
		other.ExternalDataHash = spptest.Fe(301)
		stale := auth.signature
		auth := authorizeEd25519(t, &other, publicKeyBytes(owner), owner)
		auth.signature = stale
		checkCachedWitness(t, ccs, asCustomRingEd25519(&other, auth), false)
	})
	t.Run("message_limb", func(t *testing.T) {
		changed := *a
		forged := auth
		forged.digest[31] ^= 1
		refreshEd25519PublicInputHash(t, &changed, forged.digest, zeroFields(len(a.Outputs)))
		checkCachedWitness(t, ccs, asCustomRingEd25519(&changed, forged), false)
	})
}

func TestCustomRingEd25519RejectsWrongSigner(t *testing.T) {
	ccs, a, owner := honestEd25519Ring(t)
	other := hiddenOwnerKey(0x92)
	t.Run("signature_by_other_key", func(t *testing.T) {
		checkCachedWitness(t, ccs, asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(owner), other)), false)
	})
	t.Run("other_key_signs_for_itself", func(t *testing.T) {
		checkCachedWitness(t, ccs, asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(other), other)), false)
	})
}

func TestCustomRingEd25519RejectsHiddenOwnerAsPublicSigner(t *testing.T) {
	ccs, _, owner := honestEd25519Ring(t)
	identity := hiddenOwnerIdentity(t, publicKeyBytes(owner))
	for _, slot := range []int{0, 1} {
		_, a, _ := honestEd25519Ring(t)
		a.SignerPkHashes[slot] = identity
		checkCachedWitness(t, ccs, asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(owner), owner)), false)
	}
}

func TestCustomRingEd25519RejectsPublishedOutputOwner(t *testing.T) {
	t.Run("program_commits_a_marked_owner", func(t *testing.T) {
		ccs, a, owner := honestEd25519Ring(t)
		auth := authorizeEd25519(t, a, publicKeyBytes(owner), owner)
		published := zeroFields(len(a.Outputs))
		published[0] = testSolanaPkField(t)
		refreshEd25519PublicInputHash(t, a, auth.digest, published)
		checkCachedWitness(t, ccs, asCustomRingEd25519(a, auth), false)
	})
	t.Run("default_ring_recipient", func(t *testing.T) {
		ccs, a, owner := honestEd25519Ring(t)
		a.Outputs[0].Utxo.RingProgramID = 0
		rebuildAfterOwnerChange(t, a)
		checkCachedWitness(t, ccs, asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(owner), owner)), false)
	})
}

func TestCustomRingEd25519RejectsDefaultRingHiddenInput(t *testing.T) {
	ccs, a, owner := honestEd25519Ring(t)
	a.Inputs[1].Utxo.RingProgramID = 0
	rebuildAfterOwnerChange(t, a)
	checkCachedWitness(t, ccs, asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(owner), owner)), false)
}

func TestCustomRingEd25519RejectsCacheRead(t *testing.T) {
	ccs, a, owner := honestEd25519Ring(t)
	t.Run("selected_read", func(t *testing.T) {
		cached := *a
		cached.CachedInputs = cacheReads(t, a, []int{0})
		checkCachedWitness(t, ccs, asCustomRingEd25519(&cached, authorizeEd25519(t, &cached, publicKeyBytes(owner), owner)), false)
	})
	t.Run("unselected_read", func(t *testing.T) {
		cached := *a
		cached.CachedInputs = emptyCache(t, len(a.Inputs))
		cached.CachedInputs.ReadHashes[0] = inputHash(t, a, 0)
		rechain(t, &cached.CachedInputs)
		checkCachedWitness(t, ccs, asCustomRingEd25519(&cached, authorizeEd25519(t, &cached, publicKeyBytes(owner), owner)), false)
	})
}

// The address nullifier is computable from (owner, seed) alone, so an address
// slot would link the hidden owner to every guess an observer checks.
func TestCustomRingEd25519RejectsAddressInput(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	ccs := compileEd25519Ring(t, shape)
	owner := hiddenOwnerKey(0x91)
	identity := hiddenOwnerIdentity(t, publicKeyBytes(owner))
	solAsset := protocol.SolAsset()
	a := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100)),
			sampleUtxoWithAssetAndAmount(20, solAsset, spptest.Fe(0)),
		},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(100))),
	)
	hideInput(t, a, 0, identity)
	for i := range a.Outputs {
		a.Outputs[i].Utxo.RingProgramID = a.RingProgramID
	}
	a.SignerPkHashes = asFrontendVariables(zeroFields(shape.SignerWidth()))
	a.SignerPkHashes[0] = testPayerPkHash()
	rebuildAfterOwnerChange(t, a)
	seed := spptest.Fe(0xABCDEF)
	setAddressSlot(t, &a.Inputs[1], identity, spptest.Fe(0), seed)
	finalizeAddressAssignment(t, a, true, false)

	address := protocol.Utxo{
		Domain:        spptest.Fe(AddressDomain),
		Owner:         spptest.MustOwnerHash(t, identity, spptest.MustNullifierPk(t, spptest.Fe(0))),
		Asset:         spptest.Fe(0),
		Amount:        spptest.Fe(0),
		Blinding:      seed,
		DataHash:      spptest.Fe(0),
		RingDataHash:  spptest.Fe(0),
		RingProgramID: spptest.Fe(0),
	}
	guessed := spptest.MustNullifier(t, spptest.MustUtxoHash(t, address, spptest.AsBigInt(a.inputTreeID(1))), seed, spptest.Fe(0))
	if guessed.Cmp(spptest.AsBigInt(a.Inputs[1].Nullifier)) != 0 {
		t.Fatal("the published address nullifier is not the one (owner, seed) predicts")
	}
	checkCachedWitness(t, ccs, asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(owner), owner)), false)
}

func TestCustomRingEd25519RequiresHiddenInput(t *testing.T) {
	ccs, a, owner := honestEd25519Ring(t)
	signer := testSolanaPkField(t)
	nullifierPk := spptest.MustNullifierPk(t, spptest.AsBigInt(a.Inputs[1].NullifierSecret))
	a.Inputs[1].Utxo.Owner = spptest.MustOwnerHash(t, signer, nullifierPk)
	a.Inputs[1].OwnerPkHash = signer
	a.SignerPkHashes[1] = signer
	rebuildAfterOwnerChange(t, a)
	checkCachedWitness(t, ccs, asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(owner), owner)), true)

	a.Inputs[0].Utxo.Owner = a.Inputs[1].Utxo.Owner
	a.Inputs[0].OwnerPkHash = signer
	rebuildAfterOwnerChange(t, a)
	checkCachedWitness(t, ccs, asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(owner), owner)), false)
}

// A key outside the prime subgroup or with a non-canonical encoding carries a
// signature the Go standard library accepts. The rail must still refuse it.
func TestCustomRingEd25519RejectsTorsionAndNonCanonicalKeys(t *testing.T) {
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
			ccs := compileEd25519Ring(t, shape)
			a := ed25519RingAssignment(t, shape, hiddenOwnerIdentity(t, tc.key))
			auth := authorizeEd25519(t, a, tc.key, owner)
			auth.signature = lenientSignature(tc.key, tc.secret, tc.order, auth.digest[:])
			if !ed25519.Verify(tc.key[:], auth.digest[:], auth.signature[:]) {
				t.Fatal("crypto/ed25519 rejects the forged signature, so the case proves nothing")
			}
			checkCachedWitness(t, ccs, asCustomRingEd25519(a, auth), false)
		})
	}
}

// TestCustomRingEd25519RequestFixture pins the 2x2 request the program test
// recomputes the public input hash from. Rewrite it with
//
//	UPDATE_REQUEST_FIXTURE=1 go test ./circuits/spp_transaction/shared -run TestCustomRingEd25519RequestFixture
func TestCustomRingEd25519RequestFixture(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 0)
	_, a, owner := honestEd25519Ring(t)
	circuit := asCustomRingEd25519(a, authorizeEd25519(t, a, publicKeyBytes(owner), owner))
	data, err := json.Marshal(ed25519RequestParameters(circuit))
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	var decoded transfer.Ed25519TransferParameters
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
	checkCachedWitness(t, compileEd25519Ring(t, protocol.Shape{NInputs: 2, NOutputs: 2}), witness, true)
	if os.Getenv("UPDATE_REQUEST_FIXTURE") != "" {
		if err := os.WriteFile(ed25519RingFixture, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	committed, err := os.ReadFile(ed25519RingFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, data) {
		t.Fatal("the committed Ed25519 ring request is stale; rewrite it with UPDATE_REQUEST_FIXTURE=1")
	}
}

// ed25519RequestParameters inverts Ed25519TransferParameters.CreateWitness.
func ed25519RequestParameters(c *customring.CustomRingEd25519Circuit) *transfer.Ed25519TransferParameters {
	value := spptest.AsBigInt
	values := spptest.ToBigInts
	p := &transfer.Ed25519TransferParameters{
		NInputs:          uint32(len(c.Private.Inputs)),
		NOutputs:         uint32(len(c.Private.Outputs)),
		OutputTreeID:     value(c.Public.OutputTreeID),
		ExternalDataHash: value(c.Public.ExternalDataHash),
		PrivateTxHash:    value(c.Public.PrivateTxHash),
		BlindingSeed:     value(c.Private.BlindingSeed),
		MessageHashLow:   value(c.Public.MessageHashLow),
		MessageHashHigh:  value(c.Public.MessageHashHigh),
		PublicAssets:     values(c.Public.PublicAssets[:]),
		PublicAmounts:    values(c.Public.PublicAmounts[:]),
		RingProgramID:    value(c.Public.RingProgramID),
		SignerPkHashes:   values(c.Public.SignerPkHashes),
		InputFlags:       value(c.Public.InputFlags),
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
