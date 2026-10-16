package base_test

import (
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/circuits/p256"
	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
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
			&base.CustomRingBaseCircuit{},
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

	type tamperCase struct {
		name   string
		keys   func(ringaudit.Keys) ringaudit.Keys
		tamper func(*testing.T, *base.CustomRingBaseCircuit)
	}
	tests := []tamperCase{
		{
			name: "public input hash off by one",
			tamper: func(t *testing.T, c *base.CustomRingBaseCircuit) {
				hash, ok := c.PublicInputHash.(*big.Int)
				if !ok {
					t.Fatalf("unexpected public input type %T", c.PublicInputHash)
				}
				c.PublicInputHash = new(big.Int).Add(hash, big.NewInt(1))
			},
		},
		{
			name: "private tx hash not the one in the chain",
			tamper: func(_ *testing.T, c *base.CustomRingBaseCircuit) {
				c.PrivateTxHash = big.NewInt(7)
			},
		},
		{
			name: "plaintext scalar byte flipped",
			tamper: func(_ *testing.T, c *base.CustomRingBaseCircuit) {
				c.TxViewingSk[31] = 0
			},
		},
		{
			name: "auditor key high bit set",
			tamper: func(_ *testing.T, c *base.CustomRingBaseCircuit) {
				c.AuditorPk[31] = 128
			},
		},
		{
			name: "auditor key byte changed",
			tamper: func(_ *testing.T, c *base.CustomRingBaseCircuit) {
				c.AuditorPk[0] = 6
			},
		},
		{
			name: "witnessed byte out of range",
			tamper: func(_ *testing.T, c *base.CustomRingBaseCircuit) {
				c.EphSk[0] = 256
			},
		},
		{
			// The attack shape, a well-formed key that is not the one the
			// public input hash commits to.
			name: "valid but different auditor key",
			tamper: func(t *testing.T, c *base.CustomRingBaseCircuit) {
				other := ringaudit.XPrivateKey(t, ringaudit.Scalar(0x44))
				substitute := other.PublicKey().Bytes()
				for i, value := range substitute {
					c.AuditorPk[i] = value
				}
			},
		},
		{
			name: "forged infinity for zero ephemeral secret",
			keys: func(k ringaudit.Keys) ringaudit.Keys { return k.WithForgedInfinityEphScalar(big.NewInt(0)) },
		},
		{
			name: "forged infinity for P256-order ephemeral secret",
			keys: func(k ringaudit.Keys) ringaudit.Keys { return k.WithForgedInfinityEphScalar(p256.GroupOrder()) },
		},
	}
	for name, value := range map[string]*big.Int{
		"zero":                       big.NewInt(0),
		"at the group order":         p256.GroupOrder(),
		"one above the order":        new(big.Int).Add(p256.GroupOrder(), big.NewInt(1)),
		"a valid key plus the order": new(big.Int).Add(p256.GroupOrder(), big.NewInt(0xbeef)),
	} {
		tests = append(tests, tamperCase{name: "tx scalar " + name, keys: func(k ringaudit.Keys) ringaudit.Keys { return k.WithTxScalar(t, value) }})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys := ringaudit.DefaultKeys(t)
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

func TestCircuitSolvesTheLargestTxScalar(t *testing.T) {
	largest := new(big.Int).Sub(p256.GroupOrder(), big.NewInt(1))
	solve(t, testConstraintSystem(t), buildAssignment(t, ringaudit.DefaultKeys(t).WithTxScalar(t, largest)))
}

func solve(t *testing.T, cs constraint.ConstraintSystem, assignment *base.CustomRingBaseCircuit) {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatalf("solve: %v", err)
	}
}

func validAssignment(t *testing.T) *base.CustomRingBaseCircuit {
	t.Helper()
	return buildAssignment(t, ringaudit.DefaultKeys(t))
}

func buildAssignment(t *testing.T, keys ringaudit.Keys) *base.CustomRingBaseCircuit {
	t.Helper()
	statement := keys.Statement(big.NewInt(0xabcdef))
	return &base.CustomRingBaseCircuit{
		PublicInputHash: spptest.MustHashChain(t, keys.ChainElementsFor(t, statement)),
		Audit:           statement.Audit,
		NOut:            statement.Count,
		Outputs:         statement.Outputs,
	}
}

// Clamping aliases of the ephemeral secret seal the same envelope, so no alias reaches another stream.
func TestCircuitAcceptsClampedEphemeralSecrets(t *testing.T) {
	cs := testConstraintSystem(t)
	var order [32]byte
	p256.GroupOrder().FillBytes(order[:])
	keys := ringaudit.DefaultKeys(t)
	alias := keys.EphSk()
	alias[0] ^= 0x07
	alias[31] ^= 0xc0
	for _, secret := range [][32]byte{{}, order, alias} {
		solve(t, cs, buildAssignment(t, keys.WithEphScalar(t, secret)))
	}
	statement := keys.Statement(big.NewInt(0xabcdef))
	if spptest.MustHashChain(t, keys.ChainElementsFor(t, statement)).Cmp(
		spptest.MustHashChain(t, keys.WithEphScalar(t, alias).ChainElementsFor(t, statement))) != 0 {
		t.Fatal("an ephemeral alias changed the public statement")
	}
}
