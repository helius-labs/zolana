package shared_test

import (
	"math/big"
	"testing"

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
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
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

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P2 — a masked dummy input's public owner tag must not enter the signer set:
// a data-carrying output whose tag equals the dummy's tag is not authorized.
// The dummy is tagged with the fee payer (the one non-signer participant
// AssertDummyTags allows), so the only failing constraint is the signer mask:
// the payer signed the transaction program-side but owns no input.
func TestProbeRejectsDataOutputAuthorizedByDummyInputTag(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewDefaultZoneEddsaOnlyCircuit(Shape(protocol.Shape{NInputs: 1, NOutputs: 2}))

	assignment := buildDummyInputShield(t, 125)
	makeDefaultZone(t, assignment, nil)

	// The dummy input carries the payer's public tag.
	tag := testPayerPubkeyHash()
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

// P13 — attribution: a dummy slot's public tag must name a transaction
// participant (AssertDummyTags). A dummy input or output tagged with a third
// party's pk_field would read as their spend or as a payment to them.
func TestProbeRejectsDummySlotTaggedWithThirdParty(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewDefaultZoneEddsaOnlyCircuit(Shape(protocol.Shape{NInputs: 1, NOutputs: 2}))

	// Dummy input tagged with a third party's pk_field.
	assignment := buildDummyInputShield(t, 125)
	makeDefaultZone(t, assignment, nil)
	assignment.Inputs[0].OwnerPkHash = testSolanaPkFieldSeed(t, 0x77)
	refreshDefaultZonePublicInputHash(t, assignment)
	assert.SolvingFailed(circuit, asDefaultZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))

	// Tagged with the payer instead: a participant, so the proof solves.
	assignment = buildDummyInputShield(t, 125)
	makeDefaultZone(t, assignment, nil)
	assignment.Inputs[0].OwnerPkHash = testPayerPubkeyHash()
	refreshDefaultZonePublicInputHash(t, assignment)
	assert.SolvingSucceeded(circuit, asDefaultZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
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
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P4 — an input slot with an out-of-enum domain tag must be rejected (the
// isUtxo + isAddress + isDummy == 1 decomposition).
func TestProbeRejectsInputWithInvalidDomain(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].Utxo.Domain = spptest.Fe(4)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P5 — an output slot with the address domain tag must be rejected (outputs
// are only ever spendable UTXOs or dummies).
func TestProbeRejectsAddressDomainOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Outputs[1].Utxo.Domain = spptest.Fe(AddressDomain)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
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
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P8 — a dummy output's public hash must still match its (blinded) dummy utxo
// hash: the slot binds the public transcript even though it carries nothing.
func TestProbeRejectsDummyOutputHashMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))

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
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P9 — an output amount above u64 max must be rejected by the output range
// check (a larger-than-u64 output would overflow the SPL/SOL settlement).
func TestProbeRejectsOutputAmountAboveU64(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
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

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// P10 — conservation at the boundary: five max-u64 inputs of one asset plus a
// max-u64 public deposit conserved into outputs. The field is wide enough that
// the per-asset sums cannot wrap, so this must solve.
func TestProbeConservesAtSumBoundaries(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 3}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
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

	assert.SolvingSucceeded(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
