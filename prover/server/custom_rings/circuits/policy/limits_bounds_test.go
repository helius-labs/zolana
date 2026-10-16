package policy

import (
	"math"
	"math/big"
	"testing"
)

// The outflow sums several u64 inputs, the comparison must not wrap at the cap.
func TestOutflowLimitBoundsAtU64(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inputs []uint64
		cap    uint64
		valid  bool
	}{
		{"a u64 max outflow under a u64 max cap", []uint64{math.MaxUint64}, math.MaxUint64, true},
		{"two inputs past u64 against a u64 max cap", []uint64{math.MaxUint64, 1}, math.MaxUint64, false},
		{"two inputs past u64 against a small cap", []uint64{math.MaxUint64, math.MaxUint64}, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := limitsDefault()
			f.limits.cap = tc.cap
			f.limits.rulesFree = true
			s := newStatement(t, f)
			for i, amount := range tc.inputs {
				if i == len(s.inputs) {
					extra := s.inputs[0]
					extra.Blinding = big.NewInt(int64(0x70 + i))
					s.inputs = append(s.inputs, extra)
				}
				s.inputs[i] = s.inputs[0]
				s.inputs[i].Amount = new(big.Int).SetUint64(amount)
				s.inputs[i].Blinding = big.NewInt(int64(0x70 + i))
			}
			s.inputs = s.inputs[:len(tc.inputs)]
			s.outputs[0].Amount = new(big.Int).SetUint64(tc.inputs[0])
			assignment := s.assignment(t)
			if tc.valid {
				solve(t, testConstraintSystem(t), assignment)
			} else {
				rejectAssignment(t, assignment)
			}
		})
	}
}
