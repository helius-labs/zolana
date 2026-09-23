package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/spp/spptest"
)

// The counter carries inside the window, resets across a boundary, and the
// sender's change inside the ring never counts.
func TestCircuitSolvesVelocityTransfers(t *testing.T) {
	cs := testConstraintSystem(t)
	tests := []struct {
		name string
		knob func(*velocityFixture)
	}{
		{"first spend in a window", func(v *velocityFixture) {}},
		{"the counter reaches the cap", func(v *velocityFixture) { v.spent = velocityCap - transferAmount }},
		{"a new window forgets the counter", func(v *velocityFixture) {
			v.spent = velocityCap
			v.recordWindow = windowIndex - 1
		}},
		{"an expired record opens without its counters", func(v *velocityFixture) {
			v.spent = velocityCap
			v.recordWindow = windowIndex - 1
			v.forgetCounters = true
		}},
		{"change inside the ring is not outflow", func(v *velocityFixture) {
			v.spent = velocityCap - transferAmount
			v.change = 4000
			v.rulesFree = true
		}},
		{"a large outflow raises the approval bit", func(v *velocityFixture) {
			v.cosignAbove = transferAmount - 1
			v.approval = true
		}},
		{"an outflow at the threshold needs no approval", func(v *velocityFixture) { v.cosignAbove = transferAmount }},
		{"an unlimited row still counts", func(v *velocityFixture) {
			v.cap = 0
			v.cosignAbove = transferAmount
		}},
		{"a second row for another mint", func(v *velocityFixture) {
			v.rows = []velocityRow{{asset: big.NewInt(0xe5), cap: 1}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := velocityDefault()
			tt.knob(f.velocity)
			solve(t, cs, buildAssignment(t, f))
		})
	}
}

func TestCircuitRejectsVelocityTampering(t *testing.T) {
	velocityWithoutRules := func() fixture {
		f := velocityDefault()
		f.rulesFree = true
		return f
	}
	tests := []struct {
		name  string
		build func(*testing.T) *CustomRingPolicyCircuit
	}{
		{"spend over the cap inside the window", build(velocityWithoutRules, func(v *velocityFixture) {
			v.spent = velocityCap - transferAmount + 1
		})},
		{"change leaving the ring counts as outflow", build(velocityWithoutRules, func(v *velocityFixture) {
			v.spent = velocityCap - transferAmount
			v.change = 1
			v.exit = true
			v.rulesFree = true
		})},
		{"a record from a future window", build(velocityWithoutRules, func(v *velocityFixture) { v.recordWindow = windowIndex + 1 })},
		{"a live record without its counters", build(velocityWithoutRules, func(v *velocityFixture) { v.forgetCounters = true })},
		{"the approval bit dropped above the threshold", build(velocityWithoutRules, func(v *velocityFixture) {
			v.cosignAbove = transferAmount - 1
		})},
		{"the approval bit raised below the threshold", build(velocityWithoutRules, func(v *velocityFixture) {
			v.cosignAbove = transferAmount
			v.approval = true
		})},
		{"another member's record", build(velocityWithoutRules, func(v *velocityFixture) { v.recordOwner = fill(0xb4) })},
		{"the successor keeps the spent version", build(velocityWithoutRules, func(v *velocityFixture) { v.staleSuccessor = true })},
		{"a list entry offered as the record", build(velocityWithoutRules, func(v *velocityFixture) { v.entryAsRecord = true })},
		{"a second input owner", build(velocityWithoutRules, func(v *velocityFixture) { v.secondSender = true })},
		{"two rows for one mint", build(velocityWithoutRules, func(v *velocityFixture) {
			v.rows = []velocityRow{{asset: assetField(t, fill(0xd4)), cap: velocityCap}}
		})},
		{"a row without a bound", build(velocityWithoutRules, func(v *velocityFixture) {
			v.rows = []velocityRow{{asset: big.NewInt(0xe5)}}
		})},
		{
			name: "change above the inputs",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := velocityDefault()
				f.velocity.change = 4000
				f.velocity.rulesFree = true
				return reboundStatement(t, f, func(s *statement) {
					s.inputs[0].Amount = big.NewInt(transferAmount)
				})
			},
		},
		{
			name: "the record alone",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				return reboundStatement(t, velocityDefault(), func(s *statement) {
					s.inputs = s.inputs[len(s.inputs)-1:]
				})
			},
		},
		{
			name: "a money input owned by the namespace",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				return reboundStatement(t, velocityDefault(), func(s *statement) {
					s.inputs[0].OwnerPkHash = s.inputs[1].OwnerPkHash
					s.inputs[0].NullifierPk = s.inputs[1].NullifierPk
				})
			},
		},
		{
			name: "the successor placed inside the ring",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				return reboundStatement(t, velocityDefault(), func(s *statement) {
					s.outputs[len(s.outputs)-1].RingProgramID = s.ringID
				})
			},
		},
		{
			name: "the successor under a stale window",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				return reboundStatement(t, velocityDefault(), func(s *statement) {
					s.windowIndex++
				})
			},
		},
		{
			name: "the window dropped under the policy hash",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := buildAssignment(t, velocityDefault())
				c.WindowSlots = big.NewInt(0)
				return c
			},
		},
		{
			name: "a window without rows",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				return reboundStatement(t, velocityDefault(), func(s *statement) {
					s.velocity = nil
				})
			},
		},
		{
			name: "a cap edited under the policy hash",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := buildAssignment(t, velocityDefault())
				c.Velocity[0].Cap = big.NewInt(velocityCap + 1)
				return c
			},
		},
		{
			name: "a window index on a ring without velocity",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				return reboundStatement(t, defaultFixture(), func(s *statement) {
					s.windowIndex = 1
				})
			},
		},
		{
			name: "a namespace owned output on a ring without velocity",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				return reboundStatement(t, defaultFixture(), func(s *statement) {
					s.outputs[0].OwnerPkHash = pkField(t, fill(0x11))
					s.outputs[0].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(0))
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rejectAssignment(t, tt.build(t))
		})
	}
}

func velocityDefault() fixture {
	f := defaultFixture()
	f.velocity = velocityFixtureDefault()
	return f
}

func build(base func() fixture, knob func(*velocityFixture)) func(*testing.T) *CustomRingPolicyCircuit {
	return func(t *testing.T) *CustomRingPolicyCircuit {
		f := base()
		knob(f.velocity)
		return buildAssignment(t, f)
	}
}

// Rebuilt hashes prevent rejection by the transaction commitment alone.
func reboundStatement(t *testing.T, f fixture, mutate func(*statement)) *CustomRingPolicyCircuit {
	t.Helper()
	f.rulesFree = true
	s := newStatement(t, f)
	solve(t, testConstraintSystem(t), s.assignment(t, nil))
	mutate(s)
	assignment := s.assignment(t, nil)
	if err := test.IsSolved(&velocityOpeningBindingCircuit{}, &velocityOpeningBindingCircuit{Policy: *assignment}, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("mutated transaction must retain valid opening bindings: %v", err)
	}
	return assignment
}

// Checks openings independently from the velocity predicates under test.
type velocityOpeningBindingCircuit struct {
	Policy CustomRingPolicyCircuit
}

func (c *velocityOpeningBindingCircuit) Define(api frontend.API) error {
	windowEnabled := api.Sub(1, api.IsZero(c.Policy.WindowSlots))
	c.Policy.constrainTransactionContext(api, rangecheck.New(api), windowEnabled)
	return nil
}

func TestVelocityOpeningBindingRejectsAnUncommittedMutation(t *testing.T) {
	assignment := buildAssignment(t, velocityDefault())
	assignment.Inputs[0].Amount = big.NewInt(transferAmount + 1)
	if err := test.IsSolved(&velocityOpeningBindingCircuit{}, &velocityOpeningBindingCircuit{Policy: *assignment}, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("opening-binding control admitted an amount outside the transaction commitment")
	}
}

// A row without a window caps one transfer, the record wires never charge it.
func TestCircuitSolvesTransferCaps(t *testing.T) {
	cs := testConstraintSystem(t)
	tests := []struct {
		name  string
		build func(*testing.T) *CustomRingPolicyCircuit
	}{
		{"a transfer under the cap", build(transferCapDefault, func(v *velocityFixture) {})},
		{"a transfer at the cap", build(transferCapDefault, func(v *velocityFixture) { v.cap = transferAmount })},
		{"change inside the ring is not outflow", build(transferCapDefault, func(v *velocityFixture) {
			v.change = 4000
			v.rulesFree = true
		})},
		{"a large outflow raises the approval bit", build(transferCapDefault, func(v *velocityFixture) {
			v.cosignAbove = transferAmount - 1
			v.approval = true
		})},
		{"an unlimited row still asks the co-signer", build(transferCapDefault, func(v *velocityFixture) {
			v.cap = 0
			v.cosignAbove = transferAmount - 1
			v.approval = true
		})},
		{"a second row for another mint", build(transferCapDefault, func(v *velocityFixture) {
			v.rows = []velocityRow{{asset: big.NewInt(0xe5), cap: 1}}
		})},
		{
			name: "garbage record wires do not charge the cap",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := buildAssignment(t, transferCapDefault())
				c.Record.Assets[0] = assetField(t, fill(0xd4))
				c.Record.Spent[0] = big.NewInt(velocityCap)
				c.Record.Window = big.NewInt(0)
				return c
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			solve(t, cs, tt.build(t))
		})
	}
}

func TestCircuitRejectsTransferCapTampering(t *testing.T) {
	capWithoutRules := func() fixture {
		f := transferCapDefault()
		f.rulesFree = true
		return f
	}
	tests := []struct {
		name  string
		build func(*testing.T) *CustomRingPolicyCircuit
	}{
		{"spend over the cap", build(capWithoutRules, func(v *velocityFixture) { v.cap = transferAmount - 1 })},
		{"the approval bit dropped above the threshold", build(capWithoutRules, func(v *velocityFixture) {
			v.cosignAbove = transferAmount - 1
		})},
		{"the approval bit raised below the threshold", build(capWithoutRules, func(v *velocityFixture) {
			v.cosignAbove = transferAmount
			v.approval = true
		})},
		{"a second input owner", build(capWithoutRules, func(v *velocityFixture) { v.secondSender = true })},
		{
			name: "change above the inputs",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := transferCapDefault()
				f.velocity.change = 4000
				f.velocity.rulesFree = true
				return reboundStatement(t, f, func(s *statement) {
					s.inputs[0].Amount = big.NewInt(transferAmount)
				})
			},
		},
		{
			name: "a window index without a window",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				return reboundStatement(t, transferCapDefault(), func(s *statement) {
					s.windowIndex = 1
				})
			},
		},
		{
			name: "a namespace owned note offered as a record",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				return reboundStatement(t, transferCapDefault(), func(s *statement) {
					s.inputs[1] = s.inputs[0]
					s.inputs[1].OwnerPkHash = pkField(t, fill(0x11))
					s.inputs[1].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(0))
					s.inputs[1].Blinding = big.NewInt(0x99)
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rejectAssignment(t, tt.build(t))
		})
	}
}

func transferCapDefault() fixture {
	f := defaultFixture()
	f.velocity = velocityFixtureDefault()
	f.velocity.perTransfer = true
	return f
}
