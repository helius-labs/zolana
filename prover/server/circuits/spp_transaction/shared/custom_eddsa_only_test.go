package shared_test

import (
	"math/big"
	"testing"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func MustNewCustomRingConfidentialEd25519Circuit(shape Shape) *customring.CustomRingConfidentialEd25519Circuit {
	circuit, err := customring.NewCustomRingConfidentialEd25519Circuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

// The Solana-only custom-ring circuit proves a Solana-owned transaction.
func TestCustomRingConfidentialEd25519Solves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingConfidentialEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, asCustomRingConfidentialEd25519(assignment), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		asCustomRingConfidentialEd25519(assignment),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

func TestCustomRingConfidentialEd25519PublicInputHashBindsEveryField(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingConfidentialEd25519Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	refreshHash := func() { refreshPublicInputHash(t, assignment) }
	refreshHash()

	assertPublicInputHashBindsEveryField(
		t,
		circuit,
		assignment,
		func() frontend.Circuit { return asCustomRingConfidentialEd25519(assignment) },
		refreshHash,
		publicInputHashBindingOptions{
			includeRingProgramID:       true,
			includeOutputOwnerPkHashes: true,
			signerWidth:                len(assignment.SignerPkHashes),
		},
	)
}

// Soundness guard: the Solana-only variant must reject a content slot whose
// public owner tag is the 0 sentinel for a hidden owner,
// since it has no signature gadget to authorize it. Otherwise a UTXO owned by
// OwnerHash(0, nullifier_pk) could be spent with no signature.
func TestCustomRingConfidentialEd25519RejectsZeroOwnerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingConfidentialEd25519Circuit(Shape(shape))
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

	assert.SolvingFailed(circuit, asCustomRingConfidentialEd25519(assignment), test.WithCurves(ecc.BN254))
}

// outsideRecipient is a recipient pk_field that is not a signer of the shared
// test assignment.
func outsideRecipient(t testing.TB) *big.Int {
	t.Helper()
	return testSolanaPkFieldSeed(t, 0x43)
}

// The wallet's default for an anonymous ring transaction: a dummy publishes
// zero and hides among policy-ring outputs.
func TestCustomRingConfidentialEd25519AcceptsZeroDummyOutputTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	tagDummyOutput(t, assignment, 0)
	refreshPublicInputHash(t, assignment)

	circuit := MustNewCustomRingConfidentialEd25519Circuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asCustomRingConfidentialEd25519(assignment), test.WithCurves(ecc.BN254))
}

// A fee payer that owns no input is absent from the signer vector.
// A dummy must not show it as a recipient of a transaction it only funded.
func TestCustomRingConfidentialEd25519RejectsDummyOutputPayerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	retagRealOutput(t, assignment, outsideRecipient(t))
	tagDummyOutput(t, assignment, testPayerPkHash())
	refreshPublicInputHash(t, assignment)

	circuit := MustNewCustomRingConfidentialEd25519Circuit(Shape(shape))
	assert.SolvingFailed(circuit, asCustomRingConfidentialEd25519(assignment), test.WithCurves(ecc.BN254))
}

// An owner signer is public in the signer vector, so a
// dummy may repeat it even when no output publishes it.
func TestCustomRingConfidentialEd25519AcceptsDummyOutputOwnerSignerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	retagRealOutput(t, assignment, outsideRecipient(t))
	tagDummyOutput(t, assignment, assignment.Inputs[0].OwnerPkHash)
	refreshPublicInputHash(t, assignment)

	circuit := MustNewCustomRingConfidentialEd25519Circuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asCustomRingConfidentialEd25519(assignment), test.WithCurves(ecc.BN254))
}

// A default-ring recipient is published by their real output, so a dummy may
// pose as a second payment to them.
func TestCustomRingConfidentialEd25519AcceptsDummyOutputPublishedRecipientTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	recipient := outsideRecipient(t)
	retagRealOutput(t, assignment, recipient)
	tagDummyOutput(t, assignment, recipient)
	refreshPublicInputHash(t, assignment)

	circuit := MustNewCustomRingConfidentialEd25519Circuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asCustomRingConfidentialEd25519(assignment), test.WithCurves(ecc.BN254))
}

// A policy-ring recipient publishes zero and stays private; a dummy that names
// them would copy the private identity into public data.
func TestCustomRingConfidentialEd25519RejectsDummyOutputPolicyRingRecipientTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	recipient := outsideRecipient(t)
	retagRealOutput(t, assignment, recipient)
	circuit := MustNewCustomRingConfidentialEd25519Circuit(Shape(shape))

	// Control: the same ring payment solves with an anonymous dummy.
	tagDummyOutput(t, assignment, 0)
	refreshPublicInputHash(t, assignment)
	assert.SolvingSucceeded(circuit, asCustomRingConfidentialEd25519(assignment), test.WithCurves(ecc.BN254))

	tagDummyOutput(t, assignment, recipient)
	refreshPublicInputHash(t, assignment)
	assert.SolvingFailed(circuit, asCustomRingConfidentialEd25519(assignment), test.WithCurves(ecc.BN254))
}
