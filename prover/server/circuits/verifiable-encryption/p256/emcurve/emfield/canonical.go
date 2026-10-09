// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package emfield

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

type limbKind int

const (
	limbAllOnes limbKind = iota
	limbZero
	limbOne
	limbBelowAllOnes
)

func (f *Field) AssertCanonical(e *Element) {
	if !e.IsReduced(f.widths) {
		panic("canonical check needs a reduced element")
	}
	// 1. Prefer a direct limb comparison when the modulus shape supports it.
	if f.assertBelowModulusLimbwise(e) {
		return
	}
	// 2. Otherwise hint the nonnegative gap to modulus - 1 and bound its limbs.
	inputs := f.hintInputs(nil, []*Element{e})
	pieces, err := f.api.Compiler().NewHint(modulusGapHint, f.layout.nbPiecesAll(f.widths)+1, inputs...)
	if err != nil {
		panic(err)
	}
	gap, rest := f.fromPieces(pieces, f.widths)
	carry := rest[0]
	f.api.AssertIsBoolean(carry)
	// 3. Require element + gap = modulus - 1 using a bounded carry between halves.
	maximumCanonicalValue := new(big.Int).Sub(f.mod, big.NewInt(1))
	nbLimbs, limbBits := f.layout.NbLimbs, f.layout.LimbBits
	lowLimbCount := (nbLimbs + 1) / 2
	maximumLow := new(big.Int).And(maximumCanonicalValue, new(big.Int).Sub(pow2(lowLimbCount*limbBits), big.NewInt(1)))
	maximumHigh := new(big.Int).Rsh(maximumCanonicalValue, uint(lowLimbCount*limbBits))
	sumPart := func(from, to int) frontend.Variable {
		sum := frontend.Variable(0)
		for i := from; i < to; i++ {
			sum = f.api.Add(sum, f.api.Mul(f.api.Add(e.limbs[i], gap.limbs[i]), pow2((i-from)*limbBits)))
		}
		return sum
	}
	f.api.AssertIsEqual(sumPart(0, lowLimbCount), f.api.Add(maximumLow, f.api.Mul(carry, pow2(lowLimbCount*limbBits))))
	f.api.AssertIsEqual(f.api.Add(sumPart(lowLimbCount, nbLimbs), carry), maximumHigh)
}

func (f *Field) assertBelowModulusLimbwise(e *Element) bool {
	api := f.api
	limbCount := len(f.widths)
	maximumLimbs := f.layout.decompose(new(big.Int).Sub(f.mod, big.NewInt(1)), limbCount)
	kinds := make([]limbKind, limbCount)
	for i, w := range f.widths {
		full := new(big.Int).Sub(pow2(w), big.NewInt(1))
		switch {
		case maximumLimbs[i].Cmp(full) == 0:
			kinds[i] = limbAllOnes
		case maximumLimbs[i].Sign() == 0:
			kinds[i] = limbZero
		case maximumLimbs[i].Cmp(big.NewInt(1)) == 0:
			kinds[i] = limbOne
		case i == 0 && new(big.Int).Add(maximumLimbs[i], big.NewInt(1)).Cmp(full) == 0:
			kinds[i] = limbBelowAllOnes
		default:
			return false
		}
	}
	limbs := e.limbs
	var matchesHigherLimbs frontend.Variable = 1
	for i := limbCount - 1; i >= 0; {
		switch kinds[i] {
		case limbAllOnes, limbZero:
			kind := kinds[i]
			sum := frontend.Variable(0)
			for ; i >= 0 && kinds[i] == kind; i-- {
				if kind == limbAllOnes {
					sum = api.Add(sum, api.Sub(maximumLimbs[i], limbs[i]))
				} else {
					sum = api.Add(sum, limbs[i])
				}
			}
			if kind == limbAllOnes {
				matchesHigherLimbs = api.Mul(matchesHigherLimbs, api.IsZero(sum))
			} else {
				api.AssertIsEqual(api.Mul(matchesHigherLimbs, sum), 0)
			}
		case limbOne:
			selectedLimb := api.Mul(matchesHigherLimbs, limbs[i])
			api.AssertIsEqual(api.Mul(selectedLimb, api.Sub(limbs[i], 1)), 0)
			matchesHigherLimbs = selectedLimb
			i--
		case limbBelowAllOnes:
			full := new(big.Int).Sub(pow2(f.widths[i]), big.NewInt(1))
			api.AssertIsEqual(api.Mul(matchesHigherLimbs, api.IsZero(api.Sub(full, limbs[i]))), 0)
			i--
		}
	}
	return true
}

func modulusGapHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(outputs) < 1 {
		return errors.New("missing outputs")
	}
	var value, mod *big.Int
	err := Unwrap(q, inputs, outputs[:len(outputs)-1], func(m *big.Int, _, in, out []*big.Int) error {
		if len(in) != 1 || len(out) != 1 {
			return errors.New("expecting one element")
		}
		value, mod = in[0], m
		gap := new(big.Int).Sub(m, big.NewInt(1))
		gap.Sub(gap, value)
		if gap.Sign() < 0 {
			gap.SetInt64(0)
		}
		out[0].Set(gap)
		return nil
	})
	if err != nil {
		return err
	}
	gap := new(big.Int).Sub(mod, big.NewInt(1))
	gap.Sub(gap, value)
	if gap.Sign() < 0 {
		gap.SetInt64(0)
	}
	layout, err := layoutOf(inputs)
	if err != nil {
		return err
	}
	split := uint(((layout.NbLimbs + 1) / 2) * layout.LimbBits)
	mask := new(big.Int).Sub(pow2(int(split)), big.NewInt(1))
	lowSum := new(big.Int).And(value, mask)
	lowSum.Add(lowSum, new(big.Int).And(gap, mask))
	outputs[len(outputs)-1].Rsh(lowSum, split)
	return nil
}

func init() {
	solver.RegisterHint(modulusGapHint)
}
