package shared_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark/std/math/emulated"

	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// P1 — the core double-spend: the same UTXO spent in two input slots of one
// proof (same inclusion leaf hash at two tree indices, same nullifier), with
// outputs summing to twice the real value. Everything balances; only the
// pairwise nullifier-distinctness constraint can reject it.
func TestProbeRejectsSameUtxoSpentTwiceInOneProof(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	asset := spptest.Fe(7)
	utxo := sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(100))
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{utxo, utxo},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(120)),
			sampleUtxoWithAssetAndAmount(110, asset, spptest.Fe(80)),
		},
	)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// P2 — a masked dummy input's public owner tag must not enter the signer set:
// a data-carrying output whose tag equals the dummy's tag is not authorized.
func TestProbeRejectsDataOutputAuthorizedByDummyInputTag(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewDefaultZoneEddsaOnlyCircuit(Shape(protocol.Shape{NInputs: 1, NOutputs: 2}))

	assignment := buildDummyInputShield(t, 125)

	// The dummy input carries a nonzero public tag (the program cannot mask it;
	// the circuit must).
	tag := testSolanaPkFieldSeed(t, 0x77)
	assignment.Inputs[0].OwnerPkHash = tag

	// Output 0 is real and carries data, tagged with the dummy's tag; its owner
	// recomputes from that tag so the tag binding itself holds.
	_, nullifierPk := defaultOutputOwnerTag(t)
	owner, err := protocol.OwnerHash(tag, nullifierPk)
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Outputs[0].Utxo.Owner = owner
	assignment.Outputs[0].Utxo.DataHash = spptest.Fe(0x99)
	assignment.Outputs[0].Hash = spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Outputs[0].Utxo))
	assignment.Outputs[0].OwnerPkHash = tag
	assignment.Outputs[0].NullifierPk = nullifierPk

	privateTxHash := spptest.MustPrivateTxHash(
		t,
		[]*big.Int{big.NewInt(0)},
		spptest.ToBigInts(assignment.OutputHashes()),
		noAddressHashes(1),
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	assignment.PrivateTxHash = privateTxHash
	refreshDefaultZonePublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asDefaultZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P3 — custom zone: an input UTXO that belongs to a different zone than the
// public (signing) zone must be rejected.
func TestProbeRejectsForeignZoneInput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))

	inputs, outputs := defaultBalancedUtxos(t, shape)
	inputs[0].ZoneProgramID = spptest.Fe(0xAAAA)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.ZoneProgramID = spptest.Fe(0xBBBB)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P4 — an input slot with an out-of-enum domain tag must be rejected (the
// isUtxo + isAddress + isDummy == 1 decomposition).
func TestProbeRejectsInputWithInvalidDomain(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].Utxo.Domain = spptest.Fe(4)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// P5 — an output slot with the address domain tag must be rejected (outputs
// are only ever spendable UTXOs or dummies).
func TestProbeRejectsAddressDomainOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Outputs[1].Utxo.Domain = spptest.Fe(AddressDomain)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// P6 — the custom-zone variants pin the public zone_program_id != 0 (same as
// the zone-authority variant), so a bare-UTXO transaction can never be proven
// on a zone rail with a zero zone id.
func TestProbeCustomZoneRejectsZeroZoneProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.ZoneProgramID = spptest.Fe(0)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P7 — custom zone: a bare (zone-free) UTXO must not carry zone data.
func TestProbeRejectsZoneDataOnBareUtxo(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].ZoneDataHash = spptest.Fe(0x1234)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.ZoneProgramID = spptest.Fe(0xBBBB)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P8 — a dummy output's public hash must still match its (blinded) dummy utxo
// hash: the slot binds the public transcript even though it carries nothing.
func TestProbeRejectsDummyOutputHashMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[1] = emptyOutputUtxo()
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	// Corrupt only the public hash of the dummy slot; private tx hash and
	// public input hash are refreshed over the corrupted transcript, so the
	// utxo-hash binding is the only failing constraint.
	assignment.Outputs[1].Hash = spptest.Fe(0xDEAD)

	inputHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[0].Utxo))
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		[]*big.Int{inputHash},
		spptest.ToBigInts(assignment.OutputHashes()),
		noAddressHashes(1),
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	assignment.PrivateTxHash = privateTxHash
	assignment.P256MessageHashLow, assignment.P256MessageHashHigh = spptest.MustP256MessageLimbs(t, privateTxHash)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// P9 — an output amount above u64 max must be rejected by the output range
// check (a larger-than-u64 output would overflow the SPL/SOL settlement).
func TestProbeRejectsOutputAmountAboveU64(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	asset := spptest.Fe(7)
	tooBig := new(big.Int).Lsh(big.NewInt(1), 64)
	assets, amounts := noPublicSlots()
	assets[0] = new(big.Int).Set(asset)
	amounts[0] = new(big.Int).Set(tooBig)
	assignment := buildCircuitAssignmentExact(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(0))},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, asset, tooBig),
			sampleUtxoWithAssetAndAmount(110, asset, spptest.Fe(0)),
		},
		assets,
		amounts,
	)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// P10 — conservation at the boundary: five max-u64 inputs of one asset plus a
// max-u64 public deposit conserved into outputs. The field is wide enough that
// the per-asset sums cannot wrap, so this must solve.
func TestProbeConservesAtSumBoundaries(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 3}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	asset := spptest.Fe(7)
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	inputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(10, asset, new(big.Int).Set(max)),
		sampleUtxoWithAssetAndAmount(20, asset, new(big.Int).Set(max)),
	}
	assets, amounts := noPublicSlots()
	assets[0] = new(big.Int).Set(asset)
	amounts[0] = new(big.Int).Set(max)
	assignment := buildCircuitAssignmentExact(
		t,
		shape,
		inputs,
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, asset, new(big.Int).Set(max)),
			sampleUtxoWithAssetAndAmount(110, asset, new(big.Int).Set(max)),
			sampleUtxoWithAssetAndAmount(120, asset, new(big.Int).Set(max)),
		},
		assets,
		amounts,
	)

	assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// P11 — a P256-routed ADDRESS input still requires the shared signature:
// isUtxoOrAddress covers the address kind, so an invalid P256 signature on a
// P256-owned address slot must fail.
func TestProbeRejectsP256AddressInputWithBadSignature(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)

	// Turn the P256-owned input into an address slot: pin the non-seed fields,
	// recompute the owner (nullifier secret 0), utxo hash, nullifier, and the
	// transcript hashes.
	in := &assignment.Inputs[0]
	in.Utxo.Domain = spptest.Fe(AddressDomain)
	in.Utxo.Asset = spptest.Fe(0)
	in.Utxo.Amount = spptest.Fe(0)
	in.Utxo.DataHash = spptest.Fe(0)
	in.NullifierSecret = spptest.Fe(0)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	ownerKeyHash, err := protocol.OwnerPkField(compressed)
	if err != nil {
		t.Fatalf("P256 owner key hash: %v", err)
	}
	owner, err := protocol.OwnerHash(ownerKeyHash, spptest.MustNullifierPk(t, big.NewInt(0)))
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	in.Utxo.Owner = owner
	addressHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(in.Utxo))
	in.Nullifier = spptest.MustNullifier(t, addressHash, spptest.AsBigInt(in.Utxo.Blinding), big.NewInt(0))
	nullifierTree := spptest.MustNewNullifierTree(t)
	nfWitness := spptest.MustNonInclusion(t, nullifierTree, spptest.AsBigInt(in.Nullifier))
	in.NullifierLowValue = nfWitness.LowValue
	in.NullifierNextValue = nfWitness.NextValue
	fillStateProofElements(in.NullifierLowPathElements, nfWitness.PathElements)
	in.NullifierLowPathIndex = new(big.Int).SetUint64(nfWitness.LowIndex)
	in.NullifierTreeRoot = nullifierTree.Root()

	privateTxHash := spptest.MustPrivateTxHash(
		t,
		[]*big.Int{big.NewInt(0)},
		spptest.ToBigInts(assignment.OutputHashes()),
		[]*big.Int{addressHash},
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	assignment.PrivateTxHash = privateTxHash
	assignment.P256MessageHashLow, assignment.P256MessageHashHigh = spptest.MustP256MessageLimbs(t, privateTxHash)
	refreshPublicInputHash(t, assignment)

	// Corrupt the shared signature by signing the same digest with the wrong
	// key: the address slot carries content, so its P256 routing requires
	// SigValid against the witnessed pubkey.
	digest := spptest.MustP256MessageDigest(t, privateTxHash)
	r, s, err := ecdsa.Sign(rand.Reader, spptest.FixedP256Key(t, 22), digest[:])
	if err != nil {
		t.Fatalf("sign with wrong key: %v", err)
	}
	assignment.P256Sig = P256Signature{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// P12 — the witnessed P256 key enters the signer set only when a content input
// routes to it: on a proof whose inputs are all eddsa-signed, a data-carrying
// output tagged with the (witnessed but unrouted) P256 key's pk_field is not
// authorized.
func TestProbeRejectsDataOutputAuthorizedByUnroutedP256Key(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultZoneP256Circuit(Shape(shape))

	inputs, outputs := defaultBalancedUtxos(t, shape)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)

	// Witness a real P256 key with a valid signature over the message, but keep
	// the input eddsa-tagged so the key never routes.
	priv := spptest.FixedP256Key(t, 11)
	pkField := mustP256PkField(t, priv)
	assignment.P256SigningPkField = pkField
	assignment.P256Pub = spptest.P256PubkeyAssignment(priv)

	// Output 0 carries data and is tagged with the P256 pk_field; its owner
	// recomputes from that tag, so the tag binding holds.
	_, nullifierPk := defaultOutputOwnerTag(t)
	owner, err := protocol.OwnerHash(pkField, nullifierPk)
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Outputs[0].Utxo.Owner = owner
	assignment.Outputs[0].Utxo.DataHash = spptest.Fe(0x99)
	assignment.Outputs[0].Hash = spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Outputs[0].Utxo))
	assignment.Outputs[0].OwnerPkHash = pkField
	assignment.Outputs[0].NullifierPk = nullifierPk
	assignment.Outputs[1].OwnerPkHash = testSolanaPkField(t)
	assignment.Outputs[1].NullifierPk = nullifierPk

	inputHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[0].Utxo))
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		[]*big.Int{inputHash},
		spptest.ToBigInts(assignment.OutputHashes()),
		noAddressHashes(1),
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	assignment.PrivateTxHash = privateTxHash
	assignment.P256MessageHashLow, assignment.P256MessageHashHigh = spptest.MustP256MessageLimbs(t, privateTxHash)
	refreshDefaultZonePublicInputHash(t, assignment)

	digest := spptest.MustP256MessageDigest(t, privateTxHash)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign P256 private tx hash: %v", err)
	}
	assignment.P256Sig = P256Signature{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}

	assert.SolvingFailed(circuit, asDefaultZoneP256(assignment), test.WithCurves(ecc.BN254))
}
