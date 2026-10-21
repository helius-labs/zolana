package shared_test

import (
	"testing"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// resizeSignerVector keeps the leading width slots of the assignment's signer
// vector, zero padding when the circuit is wider than the protocol width.
func resizeSignerVector(a *testAssignment, width int) {
	signers := a.TransactionSignerPkHashes()
	resized := make([]frontend.Variable, width)
	for i := range resized {
		resized[i] = 0
		if i < len(signers) {
			resized[i] = signers[i]
		}
	}
	a.SignerPkHashes = resized
}

func TestCustomRingCircuitsSizeTheSignerVectorToTheRequestedWidth(t *testing.T) {
	shape := Shape{NInputs: 2, NOutputs: 2}
	for _, width := range []int{1, 3, 7} {
		confidential, err := customring.NewCustomRingConfidentialEddsaCircuitWithSigners(shape, width)
		if err != nil {
			t.Fatal(err)
		}
		if confidential.SignerWidth != width || len(confidential.Public.SignerPkHashes) != width {
			t.Fatalf("confidential width %d: got SignerWidth %d and %d slots", width, confidential.SignerWidth, len(confidential.Public.SignerPkHashes))
		}
		anonymous, err := customring.NewCustomRingAnonymousEddsaCircuitWithSigners(shape, width)
		if err != nil {
			t.Fatal(err)
		}
		if anonymous.SignerWidth != width || len(anonymous.Public.SignerPkHashes) != width {
			t.Fatalf("anonymous width %d: got SignerWidth %d and %d slots", width, anonymous.SignerWidth, len(anonymous.Public.SignerPkHashes))
		}
	}
}

func TestCustomRingCircuitsDefaultToTheProtocolSignerWidth(t *testing.T) {
	shape := Shape{NInputs: 2, NOutputs: 2}
	confidential := MustNewCustomRingConfidentialEddsaCircuit(shape)
	anonymous := MustNewCustomRingAnonymousEddsaCircuit(shape)
	if confidential.SignerWidth != shape.SignerWidth() || len(confidential.Public.SignerPkHashes) != shape.SignerWidth() {
		t.Fatalf("confidential: got SignerWidth %d and %d slots, want %d", confidential.SignerWidth, len(confidential.Public.SignerPkHashes), shape.SignerWidth())
	}
	if anonymous.SignerWidth != shape.SignerWidth() || len(anonymous.Public.SignerPkHashes) != shape.SignerWidth() {
		t.Fatalf("anonymous: got SignerWidth %d and %d slots, want %d", anonymous.SignerWidth, len(anonymous.Public.SignerPkHashes), shape.SignerWidth())
	}
}

func TestCustomRingCircuitsRejectAZeroSignerWidth(t *testing.T) {
	shape := Shape{NInputs: 2, NOutputs: 2}
	if _, err := customring.NewCustomRingConfidentialEddsaCircuitWithSigners(shape, 0); err == nil {
		t.Fatal("confidential: zero signer width accepted")
	}
	if _, err := customring.NewCustomRingAnonymousEddsaCircuitWithSigners(shape, 0); err == nil {
		t.Fatal("anonymous: zero signer width accepted")
	}
}

// A circuit narrower or wider than the protocol width solves the same
// transaction once the public signer vector is sized to it, and a width-1
// vector still gates authorization: blanking its only slot leaves the input
// owner unsigned.
func TestCustomRingConfidentialEddsaSolvesWithACustomSignerWidth(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	for _, width := range []int{1, 4} {
		circuit, err := customring.NewCustomRingConfidentialEddsaCircuitWithSigners(Shape(shape), width)
		if err != nil {
			t.Fatal(err)
		}
		assignment := buildCircuitAssignment(t, shape)
		resizeSignerVector(assignment, width)
		refreshPublicInputHash(t, assignment)
		assert := test.NewAssert(t)
		assert.SolvingSucceeded(circuit, asCustomRingConfidentialEddsa(assignment), test.WithCurves(ecc.BN254))

		assignment.SignerPkHashes[0] = 0
		refreshPublicInputHash(t, assignment)
		assert.SolvingFailed(circuit, asCustomRingConfidentialEddsa(assignment), test.WithCurves(ecc.BN254))
	}
}

// The hidden owner authorizes every input, so the anonymous rail solves with
// a single, empty public signer slot.
func TestCustomRingAnonymousEddsaSolvesWithASingleSignerSlot(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit, err := customring.NewCustomRingAnonymousEddsaCircuitWithSigners(Shape(shape), 1)
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
	if err != nil {
		t.Fatal(err)
	}
	owner := hiddenOwnerKey(0x91)
	a := eddsaRingAssignment(t, shape, hiddenOwnerIdentity(t, publicKeyBytes(owner)))
	resizeSignerVector(a, 1)
	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(a, authorizeEddsa(t, a, owner, owner)), true)
}
