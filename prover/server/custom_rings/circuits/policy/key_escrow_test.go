package policy

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// escrowOutputs registers every UTXO output owner's key in the ring registry and turns escrow on.
func (s *statement) escrowOutputs(t *testing.T) {
	t.Helper()
	s.ctHashes = make([]*big.Int, len(s.outputs))
	for i, output := range s.outputs {
		if spptest.AsBigInt(output.Domain).Int64() != protocol.UtxoDomain {
			continue
		}
		s.ctHashes[i] = big.NewInt(int64(0xc0 + i))
		s.members.RegisterKey(t, spptest.AsBigInt(output.OwnerPkHash), spptest.AsBigInt(output.NullifierPk), s.ctHashes[i])
	}
	s.keyEscrow = true
}

func TestOutputKeysMustBeEscrowed(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *statement) *CustomRingPolicyCircuit
		passes bool
	}{
		{"registered key beside a keyless dummy output", func(t *testing.T, s *statement) *CustomRingPolicyCircuit {
			s.escrowOutputs(t)
			return s.assignment(t)
		}, true},
		{"zero key for a member without a registration", func(t *testing.T, s *statement) *CustomRingPolicyCircuit {
			s.outputs[0].NullifierPk = spptest.ZeroNullifierPk()
			s.keyEscrow = true
			return s.assignment(t)
		}, false},
		{"unregistered key with escrow off", func(t *testing.T, s *statement) *CustomRingPolicyCircuit {
			return s.assignment(t)
		}, true},
		{"unregistered key", func(t *testing.T, s *statement) *CustomRingPolicyCircuit {
			s.keyEscrow = true
			return s.assignment(t)
		}, false},
		{"ciphertext of another key", func(t *testing.T, s *statement) *CustomRingPolicyCircuit {
			s.escrowOutputs(t)
			s.ctHashes[0] = big.NewInt(0xdd)
			return s.assignment(t)
		}, false},
		{"another nullifier key under the registered ciphertext", func(t *testing.T, s *statement) *CustomRingPolicyCircuit {
			s.escrowOutputs(t)
			s.outputs[0].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(99))
			return s.assignment(t)
		}, false},
		{"escrow key claimed without a record", func(t *testing.T, s *statement) *CustomRingPolicyCircuit {
			s.escrowOutputs(t)
			c := s.assignment(t)
			c.Subjects[NInputs].Present = big.NewInt(0)
			return c
		}, false},
		{"recipient lists dropped with the key", func(t *testing.T, s *statement) *CustomRingPolicyCircuit {
			s.escrowOutputs(t)
			c := s.assignment(t)
			c.Subjects[NInputs].Lists = big.NewInt(0)
			return c
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStatement(t, defaultFixture())
			c := tt.change(t, s)
			if tt.passes {
				solve(t, testConstraintSystem(t), c)
			} else {
				rejectAssignment(t, c)
			}
		})
	}
}
