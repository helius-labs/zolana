package shared_test

import (
	"testing"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	defaultring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/default"
	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// withSignerWidth is the protocol shape for the counts with a different
// public signer vector width.
func withSignerWidth(shape protocol.Shape, width int) Shape {
	s := txShape(shape)
	s.SignerWidth = width
	return s
}

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

func TestOwnerSignedCircuitsSizeTheSignerVectorFromTheShape(t *testing.T) {
	for _, width := range []int{1, 3, 7} {
		shape := withSignerWidth(protocol.Shape{NInputs: 2, NOutputs: 2}, width)
		confidential, err := customring.NewCustomRingConfidentialEddsaCircuit(shape)
		if err != nil {
			t.Fatal(err)
		}
		anonymous, err := customring.NewCustomRingAnonymousEddsaCircuit(shape)
		if err != nil {
			t.Fatal(err)
		}
		defaultRing, err := defaultring.NewDefaultRingConfidentialEddsaCircuit(shape)
		if err != nil {
			t.Fatal(err)
		}
		for name, got := range map[string]int{
			"custom confidential":  len(confidential.Public.SignerPkHashes),
			"custom anonymous":     len(anonymous.Public.SignerPkHashes),
			"default confidential": len(defaultRing.Public.SignerPkHashes),
		} {
			if got != width {
				t.Fatalf("%s width %d: got %d slots", name, width, got)
			}
		}
	}
}

func TestOwnerSignedCircuitsRejectAZeroSignerWidth(t *testing.T) {
	shape := withSignerWidth(protocol.Shape{NInputs: 2, NOutputs: 2}, 0)
	if _, err := customring.NewCustomRingConfidentialEddsaCircuit(shape); err == nil {
		t.Fatal("custom confidential: zero signer width accepted")
	}
	if _, err := customring.NewCustomRingAnonymousEddsaCircuit(shape); err == nil {
		t.Fatal("custom anonymous: zero signer width accepted")
	}
	if _, err := defaultring.NewDefaultRingConfidentialEddsaCircuit(shape); err == nil {
		t.Fatal("default confidential: zero signer width accepted")
	}
}

// A circuit narrower or wider than the protocol width solves the same
// transaction once the public signer vector is sized to it, and a width-1
// vector still gates authorization: blanking its only slot leaves the input
// owner unsigned.
func TestCustomRingConfidentialEddsaSolvesWithACustomSignerWidth(t *testing.T) {
	host := protocol.Shape{NInputs: 1, NOutputs: 2}
	for _, width := range []int{1, 4} {
		circuit, err := customring.NewCustomRingConfidentialEddsaCircuit(withSignerWidth(host, width))
		if err != nil {
			t.Fatal(err)
		}
		assignment := buildCircuitAssignment(t, host)
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
	host := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit, err := customring.NewCustomRingAnonymousEddsaCircuit(withSignerWidth(host, 1))
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
	a := eddsaRingAssignment(t, host, hiddenOwnerIdentity(t, publicKeyBytes(owner)))
	resizeSignerVector(a, 1)
	checkCachedWitness(t, ccs, asCustomRingAnonymousEddsa(a, authorizeEddsa(t, a, owner, owner)), true)
}
