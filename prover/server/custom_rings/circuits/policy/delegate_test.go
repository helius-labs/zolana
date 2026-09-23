package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/prover-test/spp/spptest"
)

func TestDelegatePolicyKeepsRulesButExemptsVelocity(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&CustomRingDelegatePolicyCircuit{}, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		window uint64
		change func(*fixture, *statement, *[]int)
		fails  bool
	}{
		{"key escrow off", 0, func(_ *fixture, s *statement, _ *[]int) { s.keyEscrow, s.keyRegistryRoot = false, nil }, true},
		{"over per-transfer cap and threshold", 0, nil, false},
		{"over windowed cap without record", 100, nil, false},
		{"allow fact still required", 100, func(_ *fixture, _ *statement, facts *[]int) { *facts = []int{senderNotFrozen} }, true},
		{"freeze fact still required", 100, func(_ *fixture, _ *statement, facts *[]int) { *facts = []int{allowedActive} }, true},
		{"asset allow rule still required", 100, func(_ *fixture, s *statement, _ *[]int) { s.inlineAssets[0] = big.NewInt(17) }, true},
		{"approval cannot be raised", 100, func(_ *fixture, s *statement, _ *[]int) { s.approval = true }, true},
		{"window must be zero", 100, func(_ *fixture, s *statement, _ *[]int) { s.windowIndex = 1 }, true},
		{"namespace output without rules", 100, func(_ *fixture, s *statement, facts *[]int) {
			s.rules, s.inlineAssets, *facts = nil, nil, nil
			s.sources = emptySources()
			s.outputs[0].OwnerPkHash = pkField(t, fill(0x11))
			s.outputs[0].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(0))
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := defaultFixture()
			s := newStatement(t, f)
			s.windowSlots = tc.window
			s.velocity = []velocityRow{{asset: assetField(t, f.transferred), cap: 1, cosign: 1}}
			facts := f.listFacts
			s.escrowOutputs(t)
			if tc.change != nil {
				tc.change(&f, s, &facts)
			}
			s.policyHash = s.policy().hash(t)
			c := &CustomRingDelegatePolicyCircuit{Policy: *s.assignment(t, facts)}
			witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			err = cs.IsSolved(witness)
			if (err != nil) != tc.fails {
				t.Fatalf("solving error = %v, want failure %v", err, tc.fails)
			}
		})
	}
}
