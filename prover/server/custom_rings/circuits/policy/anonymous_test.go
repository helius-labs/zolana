package policy

import (
	"math/big"
	"testing"
)

// The member rail proves an anonymous trace over the policy's own openings.
func TestAnonymousPolicyDisclosesTheTransaction(t *testing.T) {
	cases := []struct {
		name   string
		change func(*statement)
		fails  bool
	}{
		{"anonymous trace", nil, false},
		{"address chain", func(s *statement) { s.addressChain = big.NewInt(5) }, true},
		{"sender not the spender", func(s *statement) { s.senderKey = fill(0x77) }, true},
		{"recipient not the owner", func(s *statement) { s.recipientKeys[0] = fill(0x78) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStatement(t, defaultFixture())
			s.anonymous = true
			if tc.change != nil {
				tc.change(s)
			}
			c := s.assignment(t)
			if tc.fails {
				rejectAssignment(t, c)
				return
			}
			solve(t, testConstraintSystem(t), c)
		})
	}
}
