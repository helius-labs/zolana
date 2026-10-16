package policy

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func TestOutflowLimitsAllowDummyInputs(t *testing.T) {
	for count := 2; count <= NInputs; count++ {
		t.Run(fmt.Sprintf("%d inputs", count), func(t *testing.T) {
			f := limitsDefault()
			f.rulesFree = true
			s := newStatement(t, f)
			s.inputs = s.inputs[:1]
			for len(s.inputs) < count {
				s.inputs = append(s.inputs, dummyOpening(t, int64(90+len(s.inputs))))
			}
			s.addressChain = spptest.MustNonZeroHashChain(t, spptest.RepeatBigInt(big.NewInt(0), count))
			if err := test.IsSolved(&CustomRingPolicyCircuit{}, s.assignment(t), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPolicyAllowsAddressClaims(t *testing.T) {
	for _, f := range []fixture{defaultFixture(), limitsDefault()} {
		f.rulesFree = true
		s := newStatement(t, f)
		s.addressChain = spptest.MustNonZeroHashChain(t, []*big.Int{big.NewInt(0), big.NewInt(0x1234)})
		if err := test.IsSolved(&CustomRingPolicyCircuit{}, s.assignment(t), ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
	}
}

// The namespace owner holds list entries only, no rail admits it in a transaction slot.
func TestPolicyRejectsNamespaceOwnedSlots(t *testing.T) {
	namespaceOwned := func(w *UtxoWires) {
		w.OwnerPkHash = pkField(t, fill(0x11))
		w.NullifierPk = spptest.MustNullifierPk(t, big.NewInt(0))
	}
	tests := []struct {
		name   string
		mutate func(*statement)
	}{
		{"an output", func(s *statement) { namespaceOwned(&s.outputs[0]) }},
		{"the sender input", func(s *statement) { namespaceOwned(&s.inputs[0]) }},
		{"a note beside the sender", func(s *statement) {
			s.inputs[1] = s.inputs[0]
			s.inputs[1].Blinding = big.NewInt(0x99)
			namespaceOwned(&s.inputs[1])
		}},
		{"an address claim", func(s *statement) {
			zero := big.NewInt(0)
			s.inputs[1] = UtxoWires{
				Domain: big.NewInt(protocol.AddressDomain), TreeID: big.NewInt(addressTreeID),
				Asset: zero, Amount: zero, DataHash: zero, RingDataHash: zero, RingProgramID: zero, Blinding: big.NewInt(0xdead),
			}
			namespaceOwned(&s.inputs[1])
			s.addressChain = spptest.MustNonZeroHashChain(t, []*big.Int{zero, big.NewInt(0x1234)})
		}},
	}
	for _, tt := range tests {
		for _, f := range []fixture{defaultFixture(), limitsDefault()} {
			t.Run(fmt.Sprintf("%s/limits=%v", tt.name, f.limits != nil), func(t *testing.T) {
				rejectAssignment(t, reboundStatement(t, f, tt.mutate))
			})
		}
	}
}
