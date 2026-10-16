package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

// A row caps the sender's outflow of one asset per transfer, the sender's change
// inside the ring never counts, and an outflow above the threshold needs approval.
func TestCircuitSolvesOutflowLimits(t *testing.T) {
	cs := testConstraintSystem(t)
	tests := []struct {
		name string
		knob func(*limitFixture)
	}{
		{"a transfer under the cap", func(v *limitFixture) {}},
		{"a transfer at the cap", func(v *limitFixture) { v.cap = transferAmount }},
		{"change inside the ring is not outflow", func(v *limitFixture) {
			v.cap = transferAmount
			v.change = 4000
			v.rulesFree = true
		}},
		{"a large outflow raises the approval bit", func(v *limitFixture) {
			v.cosignAbove = transferAmount - 1
			v.approval = true
		}},
		{"an outflow at the threshold needs no approval", func(v *limitFixture) { v.cosignAbove = transferAmount }},
		{"an uncapped row still asks the co-signer", func(v *limitFixture) {
			v.cap = 0
			v.cosignAbove = transferAmount - 1
			v.approval = true
		}},
		{"a second row for another mint", func(v *limitFixture) {
			v.rows = []limitRow{{asset: big.NewInt(0xe5), cap: 1}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := limitsDefault()
			tt.knob(f.limits)
			solve(t, cs, buildAssignment(t, f))
		})
	}
}

func TestCircuitRejectsOutflowLimitTampering(t *testing.T) {
	limitsWithoutRules := func() fixture {
		f := limitsDefault()
		f.rulesFree = true
		return f
	}
	tests := []struct {
		name  string
		build func(*testing.T) *CustomRingPolicyCircuit
	}{
		{"spend over the cap", build(limitsWithoutRules, func(v *limitFixture) { v.cap = transferAmount - 1 })},
		{"change leaving the ring counts as outflow", build(limitsWithoutRules, func(v *limitFixture) {
			v.cap = transferAmount
			v.change = 1
			v.exit = true
		})},
		{"the approval bit dropped above the threshold", build(limitsWithoutRules, func(v *limitFixture) {
			v.cosignAbove = transferAmount - 1
		})},
		{"the approval bit raised below the threshold", build(limitsWithoutRules, func(v *limitFixture) {
			v.cosignAbove = transferAmount
			v.approval = true
		})},
		{"a second input owner", build(limitsWithoutRules, func(v *limitFixture) { v.secondSender = true })},
		{"two rows for one mint", build(limitsWithoutRules, func(v *limitFixture) {
			v.rows = []limitRow{{asset: assetField(t, fill(0xd4)), cap: limitCap}}
		})},
		{"a row without a bound", build(limitsWithoutRules, func(v *limitFixture) {
			v.rows = []limitRow{{asset: big.NewInt(0xe5)}}
		})},
		{
			name: "change above the inputs",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := limitsDefault()
				f.limits.change = 4000
				f.limits.rulesFree = true
				return reboundStatement(t, f, func(s *statement) {
					s.inputs[0].Amount = big.NewInt(transferAmount)
				})
			},
		},
		{
			name: "a cap edited under the policy hash",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := buildAssignment(t, limitsDefault())
				c.Limits[0].Cap = big.NewInt(limitCap + 1)
				return c
			},
		},
		{
			name: "a row dropped under the policy hash",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := buildAssignment(t, limitsDefault())
				c.LimitCount = 0
				c.Limits[0] = OutflowLimitWires{Asset: big.NewInt(0), Cap: big.NewInt(0), CosignAbove: big.NewInt(0)}
				return c
			},
		},
		{
			name: "a padding row carrying a cap",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := buildAssignment(t, limitsDefault())
				c.Limits[1].Cap = big.NewInt(1)
				return c
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rejectAssignment(t, tt.build(t))
		})
	}
}

func limitsDefault() fixture {
	f := defaultFixture()
	f.limits = limitFixtureDefault()
	return f
}

func build(base func() fixture, knob func(*limitFixture)) func(*testing.T) *CustomRingPolicyCircuit {
	return func(t *testing.T) *CustomRingPolicyCircuit {
		f := base()
		knob(f.limits)
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
	if err := test.IsSolved(&openingBindingCircuit{}, &openingBindingCircuit{Policy: *assignment}, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("mutated transaction must retain valid opening bindings: %v", err)
	}
	return assignment
}

// Checks openings independently from the predicates under test.
type openingBindingCircuit struct {
	Policy CustomRingPolicyCircuit
}

func (c *openingBindingCircuit) Define(api frontend.API) error {
	c.Policy.constrainTransaction(api, rangecheck.New(api))
	return nil
}

func TestOpeningBindingRejectsAnUncommittedMutation(t *testing.T) {
	assignment := buildAssignment(t, limitsDefault())
	assignment.Inputs[0].Amount = big.NewInt(transferAmount + 1)
	if err := test.IsSolved(&openingBindingCircuit{}, &openingBindingCircuit{Policy: *assignment}, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("opening-binding control admitted an amount outside the transaction commitment")
	}
}
