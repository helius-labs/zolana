package customring_test

import (
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	customring "zolana/prover/circuits/custom_ring"
	"zolana/prover/circuits/custom_ring/audittest"
	"zolana/prover/circuits/verifiable-encryption/p256"
	"zolana/prover/prover-test/spp/spptest"
)

// The host side of this test recomputes the whole statement outside the circuit
// with crypto/ecdh, iden3 Poseidon (the same permutation the in-circuit gadget
// links its constants from) and crypto/aes. Solving the compiled R1CS against
// that witness is the cross-check that the circuit computes what the Rust host
// and program will recompute.

var (
	compileOnce sync.Once
	compiledCs  constraint.ConstraintSystem
	compileErr  error
)

func testConstraintSystem(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	compileOnce.Do(func() {
		start := time.Now()
		compiledCs, compileErr = frontend.Compile(
			ecc.BN254.ScalarField(),
			r1cs.NewBuilder,
			&customring.Circuit{},
			frontend.WithCompressThreshold(300),
		)
		if compileErr == nil {
			t.Logf("compiled in %s: %d constraints, %d internal variables, %d secret variables",
				time.Since(start).Round(time.Millisecond),
				compiledCs.GetNbConstraints(),
				compiledCs.GetNbInternalVariables(),
				compiledCs.GetNbSecretVariables())
		}
	})
	if compileErr != nil {
		t.Fatalf("compile: %v", compileErr)
	}
	return compiledCs
}

func TestCircuitCommitmentShape(t *testing.T) {
	cs := testConstraintSystem(t)

	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		t.Fatalf("unexpected commitments type %T", cs.GetCommitments())
	}
	// groth16-solana's BSB22 verifier supports exactly one commitment, over
	// private wires only: a committed public wire makes the vk parser reject the
	// key with Bsb22UnsupportedMultiCommitment.
	if len(commitments) != 1 {
		t.Fatalf("expected 1 BSB22 commitment, got %d", len(commitments))
	}
	if got := commitments[0].NbPublicCommitted; got != 0 {
		t.Fatalf("expected 0 public committed wires, got %d", got)
	}
	t.Logf("BSB22: 1 commitment over %d private wires", len(commitments[0].PrivateCommitted))
}

func TestCircuitSolvesValidWitness(t *testing.T) {
	cs := testConstraintSystem(t)
	assignment := validAssignment(t)

	solve(t, cs, assignment)
}

func TestCircuitRejectsTamperedWitness(t *testing.T) {
	cs := testConstraintSystem(t)

	tests := []struct {
		name   string
		keys   func(audittest.Keys) audittest.Keys
		tamper func(*testing.T, *customring.Circuit)
	}{
		{
			name: "public input hash off by one",
			tamper: func(t *testing.T, c *customring.Circuit) {
				hash, ok := c.PublicInputHash.(*big.Int)
				if !ok {
					t.Fatalf("unexpected public input type %T", c.PublicInputHash)
				}
				c.PublicInputHash = new(big.Int).Add(hash, big.NewInt(1))
			},
		},
		{
			name: "private tx hash not the one in the chain",
			tamper: func(_ *testing.T, c *customring.Circuit) {
				c.PrivateTxHash = big.NewInt(7)
			},
		},
		{
			name: "plaintext scalar byte flipped",
			tamper: func(_ *testing.T, c *customring.Circuit) {
				c.TxViewingSk[31] = 0
			},
		},
		{
			name: "auditor key off curve",
			tamper: func(_ *testing.T, c *customring.Circuit) {
				c.AuditorPk[64] = 0
			},
		},
		{
			name: "auditor key uncompressed prefix not 4",
			tamper: func(_ *testing.T, c *customring.Circuit) {
				c.AuditorPk[0] = 6
			},
		},
		{
			name: "witnessed byte out of range",
			tamper: func(_ *testing.T, c *customring.Circuit) {
				c.EphSk[0] = 256
			},
		},
		{
			// The attack shape, a well-formed key that is not the one the
			// public input hash commits to.
			name: "valid but different auditor key",
			tamper: func(t *testing.T, c *customring.Circuit) {
				other := audittest.PrivateKey(t, audittest.Scalar(0x44))
				substitute := audittest.Uncompressed(t, other.PublicKey().Bytes())
				for i, value := range substitute {
					c.AuditorPk[i] = value
				}
			},
		},
		{
			name: "tx scalar zero",
			keys: func(k audittest.Keys) audittest.Keys {
				return k.WithInfinityTxScalar(big.NewInt(0))
			},
		},
		{
			name: "tx scalar at the group order",
			keys: func(k audittest.Keys) audittest.Keys {
				return k.WithInfinityTxScalar(p256.GroupOrder())
			},
		},
		{
			name: "eph scalar zero",
			keys: func(k audittest.Keys) audittest.Keys {
				return k.WithInfinityEphScalar(big.NewInt(0))
			},
		},
		{
			name: "eph scalar at the group order",
			keys: func(k audittest.Keys) audittest.Keys {
				return k.WithInfinityEphScalar(p256.GroupOrder())
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys := audittest.DefaultKeys(t)
			if test.keys != nil {
				keys = test.keys(keys)
			}
			assignment := buildAssignment(t, keys)
			if test.tamper != nil {
				test.tamper(t, assignment)
			}

			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatalf("new witness: %v", err)
			}
			if err := cs.IsSolved(witness); err == nil {
				t.Fatal("expected the tampered witness to be rejected")
			}
		})
	}
}

func solve(t *testing.T, cs constraint.ConstraintSystem, assignment *customring.Circuit) {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatalf("solve: %v", err)
	}
}

func validAssignment(t *testing.T) *customring.Circuit {
	t.Helper()
	return buildAssignment(t, audittest.DefaultKeys(t))
}

func buildAssignment(t *testing.T, keys audittest.Keys) *customring.Circuit {
	t.Helper()
	privateTxHash := big.NewInt(0xabcdef)
	wires := keys.BlockWires(privateTxHash)
	return &customring.Circuit{
		PublicInputHash: spptest.MustHashChain(t, keys.ChainElements(t, privateTxHash)),
		PrivateTxHash:   wires.PrivateTxHash,
		TxViewingSk:     wires.TxViewingSk,
		EphSk:           wires.EphSk,
		AuditorPk:       wires.AuditorPk,
	}
}
