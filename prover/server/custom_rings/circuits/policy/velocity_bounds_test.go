package policy

import (
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/spp/spptest"
)

func TestVelocitySuccessorVersionFitsU64(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint64
		valid   bool
	}{
		{"last representable successor", math.MaxUint64 - 1, true},
		{"successor exceeds u64", math.MaxUint64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := velocityDefault()
			f.rulesFree = true
			s := newStatement(t, f)
			s.record.version = tc.version
			s.deriveRecord(t)
			s.inputs[len(s.inputs)-1].DataHash = s.record.dataHash
			s.outputs[len(s.outputs)-1].DataHash = spptest.MustPoseidon(t, 7, []*big.Int{
				SpendRecordDomain, s.record.address, s.record.sender,
				new(big.Int).Add(new(big.Int).SetUint64(tc.version), big.NewInt(1)),
				new(big.Int).SetUint64(s.windowIndex), s.record.nextCommitment,
			})
			assignment := s.assignment(t, nil)
			if err := test.IsSolved(&velocityOpeningBindingCircuit{}, &velocityOpeningBindingCircuit{Policy: *assignment}, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("opening bindings failed: %v", err)
			}
			err := test.IsSolved(&CustomRingPolicyCircuit{}, assignment, ecc.BN254.ScalarField())
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, solve=%v", tc.valid, err)
			}
		})
	}
}
