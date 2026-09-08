package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestAmountGuardGrouping(t *testing.T) {
	tests := []struct {
		name         string
		subject      int64
		guard        int64
		ownerDelta   int64
		assetDelta   int64
		secondAmount uint64
		passes       bool
	}{
		{"owner total at threshold", SubjectOutputOwner, GuardAboveAmount, 0, 0, 1000, true},
		{"owner total above threshold", SubjectOutputOwner, GuardAboveAmount, 0, 0, 1001, false},
		{"different owners have separate totals", SubjectOutputOwner, GuardAboveAmount, 1, 0, 1001, true},
		{"asset total across owners at threshold", SubjectAsset, GuardAboveAmount, 1, 0, 1000, true},
		{"asset total across owners above threshold", SubjectAsset, GuardAboveAmount, 1, 0, 1001, false},
		{"different assets have separate totals", SubjectAsset, GuardAboveAmount, 0, 1, 1001, true},
		{"owner and asset total at threshold", SubjectOutputOwner, GuardAboveAmountByAsset, 0, 0, 1000, true},
		{"owner and asset total above threshold", SubjectOutputOwner, GuardAboveAmountByAsset, 0, 0, 1001, false},
		{"owner and asset separates owners", SubjectOutputOwner, GuardAboveAmountByAsset, 1, 0, 1001, true},
		{"owner and asset separates assets", SubjectOutputOwner, GuardAboveAmountByAsset, 0, 1, 1001, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStatement(t, defaultFixture())
			s.rules = []rule{{subject: tt.subject, mode: ModePresent, mask: listMask(listApproval), guardTag: tt.guard, threshold: 2000}}
			second := s.outputs[0]
			second.OwnerPkHash = new(big.Int).Add(second.OwnerPkHash.(*big.Int), big.NewInt(tt.ownerDelta))
			second.Asset = new(big.Int).Add(second.Asset.(*big.Int), big.NewInt(tt.assetDelta))
			second.Amount = new(big.Int).SetUint64(tt.secondAmount)
			second.Blinding = big.NewInt(0x93)
			s.outputs[1] = second
			if tt.guard == GuardAboveAmountByAsset {
				s.rules[0].threshold = 0
				s.inlineLimits = []uint64{2000}
				if tt.assetDelta != 0 {
					s.inlineAssets = append(s.inlineAssets, second.Asset.(*big.Int))
					s.inlineLimits = append(s.inlineLimits, 2000)
				}
			} else if tt.subject == SubjectOutputOwner {
				s.rules = append(s.rules, rule{subject: SubjectAsset, mode: ModePresent})
			} else {
				s.inlineAssets = nil
			}
			c := s.assignment(t, nil)
			if tt.passes {
				solve(t, testConstraintSystem(t), c)
			} else {
				rejectAssignment(t, c)
			}
		})
	}
}

type amountBoundCircuit struct {
	Amounts   [NOutputs]frontend.Variable
	Threshold frontend.Variable
	AtMost    frontend.Variable
}

func (c *amountBoundCircuit) Define(api frontend.API) error {
	total := frontend.Variable(0)
	for _, amount := range c.Amounts {
		api.ToBinary(amount, amountBits)
		total = api.Add(total, amount)
	}
	api.ToBinary(c.Threshold, amountBits)
	api.AssertIsEqual(atMostAggregated(api, total, c.Threshold), c.AtMost)
	return nil
}

func TestAmountSumBounds(t *testing.T) {
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), amountBits), big.NewInt(1))
	tests := []struct {
		name      string
		amounts   [NOutputs]frontend.Variable
		threshold frontend.Variable
		atMost    int
	}{
		{"zero", [NOutputs]frontend.Variable{0, 0, 0, 0}, 0, 1},
		{"maximum threshold", [NOutputs]frontend.Variable{maximum, 0, 0, 0}, maximum, 1},
		{"one above threshold", [NOutputs]frontend.Variable{maximum, 1, 0, 0}, maximum, 0},
		{"maximum sum", [NOutputs]frontend.Variable{maximum, maximum, maximum, maximum}, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assignment := &amountBoundCircuit{Amounts: tt.amounts, Threshold: tt.threshold, AtMost: tt.atMost}
			if err := test.IsSolved(&amountBoundCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			assignment.AtMost = 1 - tt.atMost
			if err := test.IsSolved(&amountBoundCircuit{}, assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("incorrect comparison satisfied the circuit")
			}
		})
	}
}
