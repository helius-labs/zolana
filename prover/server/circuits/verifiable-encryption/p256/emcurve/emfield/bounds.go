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
	"math/big"
)

func polyMulAbs(a, b []*big.Int) []*big.Int {
	out := make([]*big.Int, len(a)+len(b)-1)
	for i := range out {
		out[i] = new(big.Int)
	}
	for i := range a {
		for j := range b {
			out[i+j].Add(out[i+j], new(big.Int).Mul(a[i], b[j]))
		}
	}
	return out
}

func addInto(destination []*big.Int, source []*big.Int) []*big.Int {
	for len(destination) < len(source) {
		destination = append(destination, new(big.Int))
	}
	for i := range source {
		destination[i].Add(destination[i], source[i])
	}
	return destination
}

func intervalMul(aMin, aMax, bMin, bMax *big.Int) (*big.Int, *big.Int) {
	products := []*big.Int{
		new(big.Int).Mul(aMin, bMin), new(big.Int).Mul(aMin, bMax),
		new(big.Int).Mul(aMax, bMin), new(big.Int).Mul(aMax, bMax),
	}
	lo, hi := products[0], products[0]
	for _, product := range products[1:] {
		if product.Cmp(lo) < 0 {
			lo = product
		}
		if product.Cmp(hi) > 0 {
			hi = product
		}
	}
	return lo, hi
}

func termRange(t term) (*big.Int, *big.Int) {
	lo, hi := big.NewInt(1), big.NewInt(1)
	for i, e := range t.factors {
		if i > 0 && e == t.factors[i-1] && len(t.factors) == 2 {
			m := absMax(e.valueMin, e.valueMax)
			sq := new(big.Int).Mul(m, m)
			if e.valueMin.Sign() >= 0 {
				lo, hi = new(big.Int).Mul(e.valueMin, e.valueMin), new(big.Int).Mul(e.valueMax, e.valueMax)
			} else if e.valueMax.Sign() <= 0 {
				lo, hi = new(big.Int).Mul(e.valueMax, e.valueMax), new(big.Int).Mul(e.valueMin, e.valueMin)
			} else {
				lo, hi = new(big.Int), sq
			}
			continue
		}
		lo, hi = intervalMul(lo, hi, e.valueMin, e.valueMax)
	}
	lo.Mul(lo, t.coef)
	hi.Mul(hi, t.coef)
	if t.coef.Sign() < 0 {
		lo, hi = hi, lo
	}
	return lo, hi
}

func limbAbs(e *Element) []*big.Int {
	out := make([]*big.Int, len(e.limbs))
	for i := range out {
		out[i] = absMax(e.lo[i], e.hi[i])
	}
	return out
}

func signed(v, q *big.Int) *big.Int {
	half := new(big.Int).Rsh(q, 1)
	if v.Cmp(half) > 0 {
		return new(big.Int).Sub(v, q)
	}
	return new(big.Int).Set(v)
}
