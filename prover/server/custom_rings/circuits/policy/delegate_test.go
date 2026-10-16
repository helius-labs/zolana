package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func TestDelegatePolicyKeepsRulesButExemptsOutflowLimits(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&CustomRingDelegatePolicyCircuit{}, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*statement)
		fails  bool
	}{
		{"key escrow off", func(s *statement) { s.keyEscrow = false }, true},
		{"over the cap and the co-sign threshold", nil, false},
		{"allow list still required", func(s *statement) { s.setLists(t, s.members, pkField(t, allowedKey), 0) }, true},
		{"freeze list still required", func(s *statement) { s.setLists(t, s.curator, s.sender, listMask(listFrozen)) }, true},
		{"asset allow rule still required", func(s *statement) { s.inlineAssets[0] = big.NewInt(17) }, true},
		{"approval cannot be raised", func(s *statement) { s.approval = true }, true},
		{"a row without a bound", func(s *statement) { s.limits[0].cap, s.limits[0].cosign = 0, 0 }, true},
		{"namespace output without rules", func(s *statement) {
			s.rules, s.inlineAssets = nil, nil
			s.sources = emptySources()
			s.outputs[0].OwnerPkHash = pkField(t, fill(0x11))
			s.outputs[0].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(0))
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := defaultFixture()
			s := newStatement(t, f)
			s.limits = []limitRow{{asset: assetField(t, f.transferred), cap: 1, cosign: 1}}
			s.escrowOutputs(t)
			if tc.change != nil {
				tc.change(s)
			}
			c := &CustomRingDelegatePolicyCircuit{Policy: *s.assignment(t)}
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
