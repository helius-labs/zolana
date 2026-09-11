package policy

import (
	"math/big"
	"testing"

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
			solve(t, cs, velocityAssignment(t, f))
		})
	}
}

func TestCircuitRejectsVelocityTampering(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T) *CustomRingPolicyCircuit
	}{
		{"spend over the cap inside the window", velocityBuild(func(v *velocityFixture) {
			v.spent = velocityCap - transferAmount + 1
		})},
		{"change leaving the ring counts as outflow", velocityBuild(func(v *velocityFixture) {
			v.spent = velocityCap - transferAmount
			v.change = 1
			v.exit = true
			v.rulesFree = true
		})},
		{"a record from a future window", velocityBuild(func(v *velocityFixture) { v.recordWindow = windowIndex + 1 })},
		{"a live record without its counters", velocityBuild(func(v *velocityFixture) { v.forgetCounters = true })},
		{"the approval bit dropped above the threshold", velocityBuild(func(v *velocityFixture) {
			v.cosignAbove = transferAmount - 1
		})},
		{"the approval bit raised below the threshold", velocityBuild(func(v *velocityFixture) {
			v.cosignAbove = transferAmount
			v.approval = true
		})},
		{"another member's record", velocityBuild(func(v *velocityFixture) { v.recordOwner = fill(0xb4) })},
		{"the successor keeps the spent version", velocityBuild(func(v *velocityFixture) { v.staleSuccessor = true })},
		{"a list entry offered as the record", velocityBuild(func(v *velocityFixture) { v.entryAsRecord = true })},
		{"a second input owner", velocityBuild(func(v *velocityFixture) { v.secondSender = true })},
		{"two rows for one mint", velocityBuild(func(v *velocityFixture) {
			v.rows = []velocityRow{{asset: assetField(t, fill(0xd4)), cap: 1}}
		})},
		{"a row without a bound", velocityBuild(func(v *velocityFixture) {
			v.rows = []velocityRow{{asset: big.NewInt(0xe5)}}
		})},
		{
			name: "change above the inputs",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := velocityDefault()
				f.velocity.change = 10
				f.velocity.rulesFree = true
				c := velocityAssignment(t, f)
				c.Inputs[0].Amount = big.NewInt(transferAmount)
				return c
			},
		},
		{
			name: "the record alone",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := velocityAssignment(t, velocityDefault())
				c.InputCountSelected[1] = big.NewInt(0)
				c.InputCountSelected[0] = big.NewInt(1)
				return c
			},
		},
		{
			name: "a money input owned by the namespace",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := velocityAssignment(t, velocityDefault())
				c.Inputs[0].OwnerPkHash = c.Inputs[1].OwnerPkHash
				c.Inputs[0].NullifierPk = c.Inputs[1].NullifierPk
				return c
			},
		},
		{
			name: "the record opened in the money tree",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := velocityAssignment(t, velocityDefault())
				c.Inputs[1].TreeID = big.NewInt(0)
				return c
			},
		},
		{
			name: "the successor placed inside the ring",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := velocityAssignment(t, velocityDefault())
				c.Outputs[2].RingProgramID = c.RingID
				return c
			},
		},
		{
			name: "the successor under a stale window",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := velocityAssignment(t, velocityDefault())
				c.WindowIndex = big.NewInt(windowIndex + 1)
				return c
			},
		},
		{
			name: "rows without a window",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := velocityAssignment(t, velocityDefault())
				c.WindowSlots = big.NewInt(0)
				return c
			},
		},
		{
			name: "a window without rows",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := velocityAssignment(t, velocityDefault())
				c.VelocityCountSelected[1] = big.NewInt(0)
				c.VelocityCountSelected[0] = big.NewInt(1)
				return c
			},
		},
		{
			name: "a cap edited under the policy hash",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := velocityAssignment(t, velocityDefault())
				c.Velocity[0].Cap = big.NewInt(velocityCap + 1)
				return c
			},
		},
		{
			name: "a window index on a ring without velocity",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.WindowIndex = big.NewInt(1)
				return c
			},
		},
		{
			name: "a namespace owned output on a ring without velocity",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.Outputs[0].OwnerPkHash = pkField(t, fill(0x11))
				c.Outputs[0].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(0))
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

func velocityDefault() fixture {
	f := defaultFixture()
	f.velocity = velocityFixtureDefault()
	return f
}

func velocityBuild(knob func(*velocityFixture)) func(*testing.T) *CustomRingPolicyCircuit {
	return func(t *testing.T) *CustomRingPolicyCircuit {
		f := velocityDefault()
		knob(f.velocity)
		return velocityAssignment(t, f)
	}
}

// velocityAssignment drops the counters from the witness when the fixture
// forgets them.
func velocityAssignment(t *testing.T, f fixture) *CustomRingPolicyCircuit {
	t.Helper()
	listFacts := f.listFacts
	if f.velocity.rulesFree {
		f.rulesFree = true
		listFacts = nil
	}
	s := newStatement(t, f)
	c := s.assignment(t, listFacts)
	if f.velocity.forgetCounters {
		c.Record.Salt = big.NewInt(0)
		for i := range c.Record.Spent {
			c.Record.Assets[i] = big.NewInt(0)
			c.Record.Spent[i] = big.NewInt(0)
		}
	}
	return c
}
