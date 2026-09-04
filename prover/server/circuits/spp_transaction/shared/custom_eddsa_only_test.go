package shared_test

import (
	"math/big"
	"testing"

	customring "zolana/prover/circuits/spp_transaction/custom"
	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func MustNewCustomRingEddsaOnlyCircuit(shape Shape) *customring.CustomRingEddsaOnlyCircuit {
	circuit, err := customring.NewCustomRingEddsaOnlyCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

// The Solana-only custom-ring circuit proves a Solana-owned transaction.
func TestCustomRingEddsaOnlySolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		asCustomRingEddsaOnly(assignment),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

func TestCustomRingEddsaOnlyPublicInputHashBindsEveryField(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	refreshHash := func() { refreshPublicInputHash(t, assignment) }
	refreshHash()

	assertPublicInputHashBindsEveryField(
		t,
		circuit,
		assignment,
		func() frontend.Circuit { return asCustomRingEddsaOnly(assignment) },
		refreshHash,
		publicInputHashBindingOptions{
			includeRingProgramID:       true,
			includeOutputOwnerPkHashes: true,
			signerWidth:                len(assignment.SignerPkHashes),
		},
	)
}

// Soundness guard: the Solana-only variant must reject a content slot whose
// public owner tag is the 0 sentinel (the dropped P256 rail's routing mark),
// since it has no signature gadget to authorize it. Otherwise a UTXO owned by
// OwnerHash(0, nullifier_pk) could be spent with no signature.
func TestCustomRingEddsaOnlyRejectsZeroOwnerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)

	nullifierSecret := spptest.AsBigInt(assignment.Inputs[0].NullifierSecret)
	nullifierPk := spptest.MustNullifierPk(t, nullifierSecret)
	owner, err := protocol.OwnerHash(big.NewInt(0), nullifierPk)
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Inputs[0].Utxo.Owner = owner
	assignment.Inputs[0].OwnerPkHash = spptest.Fe(0)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// outsideRecipient is a recipient pk_field that is not a signer of the shared
// test assignment.
func outsideRecipient(t testing.TB) *big.Int {
	t.Helper()
	return testSolanaPkFieldSeed(t, 0x43)
}

// The wallet's default for an anonymous ring transaction: a dummy publishes
// zero and hides among policy-ring outputs.
func TestCustomRingEddsaOnlyAcceptsZeroDummyOutputTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	tagDummyOutput(t, assignment, 0)
	refreshPublicInputHash(t, assignment)

	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// The payer signs but never serves as a dummy marker: a fee sponsor must not
// be shown as a ring recipient by a transaction it only paid for.
func TestCustomRingEddsaOnlyRejectsDummyOutputPayerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	retagRealOutput(t, assignment, outsideRecipient(t))
	tagDummyOutput(t, assignment, assignment.TransactionSignerPkHashes()[0])
	refreshPublicInputHash(t, assignment)

	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// An owner signer other than the payer is public in the signer vector, so a
// dummy may repeat it even when no output publishes it.
func TestCustomRingEddsaOnlyAcceptsDummyOutputOwnerSignerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	retagRealOutput(t, assignment, outsideRecipient(t))
	tagDummyOutput(t, assignment, assignment.Inputs[0].OwnerPkHash)
	refreshPublicInputHash(t, assignment)

	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A default-ring recipient is published by their real output, so a dummy may
// pose as a second payment to them.
func TestCustomRingEddsaOnlyAcceptsDummyOutputPublishedRecipientTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	recipient := outsideRecipient(t)
	retagRealOutput(t, assignment, recipient)
	tagDummyOutput(t, assignment, recipient)
	refreshPublicInputHash(t, assignment)

	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A policy-ring recipient publishes zero and stays private; a dummy that names
// them would copy the private identity into public data.
func TestCustomRingEddsaOnlyRejectsDummyOutputPolicyRingRecipientTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	recipient := outsideRecipient(t)
	retagRealOutput(t, assignment, recipient)
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))

	// Control: the same ring payment solves with an anonymous dummy.
	tagDummyOutput(t, assignment, 0)
	refreshPublicInputHash(t, assignment)
	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))

	tagDummyOutput(t, assignment, recipient)
	refreshPublicInputHash(t, assignment)
	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
