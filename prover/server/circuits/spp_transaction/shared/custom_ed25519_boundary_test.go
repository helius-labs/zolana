package shared_test

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var (
	ed25519BoundaryShape = protocol.Shape{NInputs: 1, NOutputs: 2}
	ed25519MixedShape    = protocol.Shape{NInputs: 2, NOutputs: 2}
)

type compiledEd25519System struct {
	once sync.Once
	ccs  constraint.ConstraintSystem
	err  error
}

var compiledEd25519Systems sync.Map

func compiledCustomRingEd25519(t testing.TB, shape protocol.Shape) constraint.ConstraintSystem {
	t.Helper()
	entry, _ := compiledEd25519Systems.LoadOrStore(shape, &compiledEd25519System{})
	compiled := entry.(*compiledEd25519System)
	compiled.once.Do(func() {
		start := time.Now()
		compiled.ccs, compiled.err = frontend.Compile(
			ecc.BN254.ScalarField(),
			r1cs.NewBuilder,
			MustNewCustomRingEd25519Circuit(Shape(shape)),
			frontend.WithCompressThreshold(300),
		)
		if compiled.err == nil {
			t.Logf(
				"compiled CustomRingEd25519 %dx%d: %d constraints in %s",
				shape.NInputs, shape.NOutputs, compiled.ccs.GetNbConstraints(), time.Since(start).Round(time.Millisecond),
			)
		}
	})
	if compiled.err != nil {
		t.Fatalf("compile CustomRingEd25519 %dx%d: %v", shape.NInputs, shape.NOutputs, compiled.err)
	}
	return compiled.ccs
}

func solveCustomRingEd25519(ccs constraint.ConstraintSystem, assignment frontend.Circuit, opts ...solver.Option) error {
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("new witness: %w", err)
	}
	return ccs.IsSolved(w, opts...)
}

func assertCustomRingEd25519Solves(t *testing.T, ccs constraint.ConstraintSystem, assignment frontend.Circuit) {
	t.Helper()
	start := time.Now()
	if err := solveCustomRingEd25519(ccs, assignment); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
	t.Logf("solved in %s", time.Since(start).Round(time.Millisecond))
}

// assertCustomRingEd25519Rejected accepts a rejection by a constraint or by an
// honest hint refusing the input; forged hint outputs for the gadget are
// covered by circuits/ed25519/soundness_test.go.
func assertCustomRingEd25519Rejected(t *testing.T, ccs constraint.ConstraintSystem, assignment frontend.Circuit) {
	t.Helper()
	err := solveCustomRingEd25519(ccs, assignment)
	if err == nil {
		t.Fatal("accepted")
	}
	t.Logf("rejected: %s", firstLine(err.Error()))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func ed25519Digest(authorization ed25519Authorization) [32]byte {
	var digest [32]byte
	authorization.high.FillBytes(digest[:16])
	authorization.low.FillBytes(digest[16:])
	return digest
}

func honestEd25519Assignment(t testing.TB, shape protocol.Shape, owner ed25519.PrivateKey) (*testAssignment, ed25519Authorization) {
	t.Helper()
	assignment := buildCircuitAssignment(t, shape)
	rewriteInputAsEd25519(t, assignment, 0, owner)
	return assignment, authorizeEd25519(t, assignment, owner, owner)
}

// ed25519L is the prime order of the Ed25519 base point.
func ed25519L() *big.Int {
	l, _ := new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	return l
}

func littleEndian32(v *big.Int) [32]byte {
	var out [32]byte
	v.FillBytes(out[:])
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// The identity point (y = 1) with R = identity and S = 0 satisfies the
// cofactorless equation [S]B = R + [h]A for every message. The gadget rejects
// small-order keys, so the identity of that key cannot be spent.
func TestCustomRingEd25519RejectsSmallOrderPublicKey(t *testing.T) {
	ccs := compiledCustomRingEd25519(t, ed25519BoundaryShape)
	owner := spptest.FixedEd25519Key(t, 11)

	t.Run("honest witness solves", func(t *testing.T) {
		assignment, authorization := honestEd25519Assignment(t, ed25519BoundaryShape, owner)
		assertCustomRingEd25519Solves(t, ccs, asCustomRingEd25519(assignment, authorization))
	})

	t.Run("identity key with the trivial signature", func(t *testing.T) {
		var identityKey [32]byte
		identityKey[0] = 1
		identity, err := protocol.SolanaPkField(identityKey)
		if err != nil {
			t.Fatalf("identity key hash: %v", err)
		}
		assignment := buildCircuitAssignment(t, ed25519BoundaryShape)
		rewriteInputAsEd25519WithIdentity(t, assignment, 0, identity)
		authorization := authorizeEd25519(t, assignment, owner, owner)
		authorization.pub = identityKey
		authorization.sig = [64]byte{}
		authorization.sig[0] = 1
		authorization.pkHash = identity
		refreshCustomRingEd25519PublicInputHash(t, assignment, ed25519Digest(authorization), identity)
		assertCustomRingEd25519Rejected(t, ccs, asCustomRingEd25519(assignment, authorization))
	})
}

// S must be the canonical scalar below L; S + L is the classic malleated
// signature and S = L a boundary value.
func TestCustomRingEd25519RejectsNonCanonicalSignatureScalar(t *testing.T) {
	ccs := compiledCustomRingEd25519(t, ed25519BoundaryShape)
	owner := spptest.FixedEd25519Key(t, 11)
	assignment, honest := honestEd25519Assignment(t, ed25519BoundaryShape, owner)
	l := ed25519L()
	s := honest.sig[32:]
	sLE := make([]byte, 32)
	copy(sLE, s)
	for i, j := 0, len(sLE)-1; i < j; i, j = i+1, j-1 {
		sLE[i], sLE[j] = sLE[j], sLE[i]
	}
	sValue := new(big.Int).SetBytes(sLE)

	t.Run("honest witness solves", func(t *testing.T) {
		assertCustomRingEd25519Solves(t, ccs, asCustomRingEd25519(assignment, honest))
	})
	for _, row := range []struct {
		name  string
		value *big.Int
	}{
		{"s plus group order", new(big.Int).Add(sValue, l)},
		{"s equals group order", l},
		{"s zero", new(big.Int)},
	} {
		t.Run(row.name, func(t *testing.T) {
			authorization := honest
			encoded := littleEndian32(row.value)
			copy(authorization.sig[32:], encoded[:])
			assertCustomRingEd25519Rejected(t, ccs, asCustomRingEd25519(assignment, authorization))
		})
	}
}

func withEd25519DataOutput(t testing.TB, assignment *testAssignment, owner ed25519.PrivateKey) {
	t.Helper()
	assignment.Outputs[0].Utxo.DataHash = spptest.Fe(0xDA7A)
	rewriteOutputAsEd25519(t, assignment, 0, owner)
}

func TestCustomRingEd25519RejectsOutputOnlyEd25519Owner(t *testing.T) {
	ccs := compiledCustomRingEd25519(t, ed25519BoundaryShape)
	owner := spptest.FixedEd25519Key(t, 11)
	wrongSigner := spptest.FixedEd25519Key(t, 12)

	t.Run("Ed25519 input authorizes a data output", func(t *testing.T) {
		assignment := buildCircuitAssignment(t, ed25519BoundaryShape)
		rewriteInputAsEd25519(t, assignment, 0, owner)
		withEd25519DataOutput(t, assignment, owner)
		assertCustomRingEd25519Solves(t, ccs, asCustomRingEd25519(assignment, authorizeEd25519(t, assignment, owner, owner)))
	})
	for _, row := range []struct {
		name   string
		signer ed25519.PrivateKey
	}{
		{"runtime-signed input with a valid in-circuit signature", owner},
		{"runtime-signed input with an in-circuit signature from another key", wrongSigner},
	} {
		t.Run(row.name, func(t *testing.T) {
			assignment := buildCircuitAssignment(t, ed25519BoundaryShape)
			withEd25519DataOutput(t, assignment, owner)
			if spptest.AsBigInt(assignment.Inputs[0].OwnerPkHash).Sign() == 0 {
				t.Fatal("input 0 must stay runtime-signed")
			}
			assertCustomRingEd25519Rejected(t, ccs, asCustomRingEd25519(assignment, authorizeEd25519(t, assignment, owner, row.signer)))
		})
	}
}

func TestCustomRingEd25519RejectsUnsignedSharedInputBesideRuntimeInput(t *testing.T) {
	ccs := compiledCustomRingEd25519(t, ed25519MixedShape)
	owner := spptest.FixedEd25519Key(t, 11)
	wrongSigner := spptest.FixedEd25519Key(t, 12)
	build := func(t *testing.T) *testAssignment {
		t.Helper()
		assignment := buildCircuitAssignment(t, ed25519MixedShape)
		rewriteInputAsEd25519(t, assignment, 0, owner)
		withEd25519DataOutput(t, assignment, owner)
		if spptest.AsBigInt(assignment.Inputs[1].OwnerPkHash).Sign() == 0 {
			t.Fatal("input 1 must stay runtime-signed")
		}
		return assignment
	}

	t.Run("valid signature solves", func(t *testing.T) {
		assignment := build(t)
		assertCustomRingEd25519Solves(t, ccs, asCustomRingEd25519(assignment, authorizeEd25519(t, assignment, owner, owner)))
	})
	t.Run("signature from another key", func(t *testing.T) {
		assignment := build(t)
		assertCustomRingEd25519Rejected(t, ccs, asCustomRingEd25519(assignment, authorizeEd25519(t, assignment, owner, wrongSigner)))
	})
	t.Run("signature R zero", func(t *testing.T) {
		assignment := build(t)
		authorization := authorizeEd25519(t, assignment, owner, owner)
		clear(authorization.sig[:32])
		assertCustomRingEd25519Rejected(t, ccs, asCustomRingEd25519(assignment, authorization))
	})
}
