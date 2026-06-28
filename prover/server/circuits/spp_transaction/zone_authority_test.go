package transaction_test

import (
	"math/big"
	"testing"

	. "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

// zoneAuthorityZone is the non-zero policy-zone id the zone-authority assignments
// bind to. zone_authority_transact is always a zone instruction, so SPP supplies
// a non-zero ZoneProgramID (the zone_config program_id) and the circuit pins it
// non-zero.
func zoneAuthorityZone() *big.Int { return spptest.Fe(0x5a) }

// The zone-authority variant (zone_authority_transact) is the Solana-only zone
// transfer with no in-circuit signature and every input owner pk_field kept
// private. A balanced assignment whose owners bind to their nullifier secrets --
// the only in-circuit constraint, the zone authorizes the spend on-chain -- solves
// for every supported shape.
func TestZoneAuthorityCircuitSolvesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
			if err != nil {
				t.Fatalf("new zone-authority circuit: %v", err)
			}
			assignment := buildZoneAuthorityAssignment(t, shape)
			assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
		})
	}
}

// End-to-end Groth16 prove/verify on a representative shape confirms the variant
// produces a valid proof against its own public-input layout.
func TestZoneAuthorityCircuitProves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 3, NOutputs: 3}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	assignment := buildZoneAuthorityAssignment(t, shape)
	assert.ProverSucceeded(
		circuit,
		assignment,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

// Soundness: even without a signature, the nullifier is bound to the UTXO through
// the owner-hash binding (owner = OwnerHash(owner_pk_field,
// Poseidon(nullifier_secret))). Spending an input whose nullifier secret does not
// match its owner hash must fail.
func TestZoneAuthorityCircuitRejectsWrongNullifierSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	assignment := buildZoneAuthorityAssignment(t, shape)
	// Break the owner-hash binding: change the secret without re-deriving owner.
	assignment.Inputs[0].NullifierSecret = spptest.Fe(12345)
	refreshZoneAuthorityPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Ownership: the authority variant binds every real input's zone_program_id to
// the public ZoneProgramID with no zero exemption, so a default-zone (zero) input
// cannot be spent through zone_authority_transact even though zone_transact's
// bindIfSet would have exempted it. Inputs carry zone_program_id == 0 while the
// public ZoneProgramID is the non-zero zone; the mismatch must make the solve fail.
func TestZoneAuthorityCircuitRejectsDefaultZoneInput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	assignment := buildZoneAuthorityAssignmentWithZone(t, shape, zoneAuthorityZone(), big.NewInt(0))

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// zone_authority_transact is always a zone instruction, so the circuit pins the
// public ZoneProgramID non-zero. A zero ZoneProgramID (which would let the strict
// input binding be satisfied by default-zone UTXOs) must be rejected even when
// every UTXO's zone field is also zero.
func TestZoneAuthorityCircuitRejectsZeroZoneProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	assignment := buildZoneAuthorityAssignmentWithZone(t, shape, big.NewInt(0), big.NewInt(0))

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Output containment: zone_authority_transact keeps every output in the zone
// (strict binding, like inputs), so an output that drops to the default zone
// (zone_program_id == 0) while the public ZoneProgramID is non-zero must fail --
// the authority cannot move value out of the policy zone. Inputs stay in the zone
// to isolate the failure to the output.
func TestZoneAuthorityCircuitRejectsDefaultZoneOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	zone := zoneAuthorityZone()
	assignment := buildZoneAuthorityAssignmentZones(t, shape, zone, zone, big.NewInt(0))

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// buildZoneAuthorityAssignment builds the canonical zone-authority assignment: a
// balanced Solana-owner transfer whose every UTXO is in the non-zero policy zone,
// matching the public ZoneProgramID.
func buildZoneAuthorityAssignment(t testing.TB, shape protocol.Shape) *Circuit {
	t.Helper()
	zone := zoneAuthorityZone()
	return buildZoneAuthorityAssignmentWithZone(t, shape, zone, zone)
}

// buildZoneAuthorityAssignmentWithZone builds a zone-authority assignment whose
// every UTXO carries utxoZone and whose public ZoneProgramID is publicZone.
func buildZoneAuthorityAssignmentWithZone(t testing.TB, shape protocol.Shape, publicZone, utxoZone *big.Int) *Circuit {
	t.Helper()
	return buildZoneAuthorityAssignmentZones(t, shape, publicZone, utxoZone, utxoZone)
}

// buildZoneAuthorityAssignmentZones builds a zone-authority assignment whose input
// UTXOs carry inputZone, output UTXOs carry outputZone, and public ZoneProgramID
// is publicZone. It zeroes the P256 message limbs (no signature on this rail) and
// recomputes the public-input hash with the zone-authority layout (input owner
// pk_fields omitted).
func buildZoneAuthorityAssignmentZones(t testing.TB, shape protocol.Shape, publicZone, inputZone, outputZone *big.Int) *Circuit {
	t.Helper()
	inputs, outputs := defaultBalancedUtxos(t, shape)
	for i := range inputs {
		inputs[i].ZoneProgramID = new(big.Int).Set(inputZone)
	}
	for i := range outputs {
		outputs[i].ZoneProgramID = new(big.Int).Set(outputZone)
	}
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	assignment.ZoneProgramID = new(big.Int).Set(publicZone)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshZoneAuthorityPublicInputHash(t, assignment)
	return assignment
}

func refreshZoneAuthorityPublicInputHash(t testing.TB, assignment *Circuit) {
	refreshPublicInputHashVariant(t, assignment, false, true)
}
