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

type Term struct {
	Coef    int64
	Factors []*Element
}

func T(coef int64, factors ...*Element) Term {
	return Term{Coef: coef, Factors: factors}
}

type term struct {
	coef    *big.Int
	factors []*Element
}

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

func addInto(dst []*big.Int, src []*big.Int) []*big.Int {
	for len(dst) < len(src) {
		dst = append(dst, new(big.Int))
	}
	for i := range src {
		dst[i].Add(dst[i], src[i])
	}
	return dst
}

func intervalMul(alo, ahi, blo, bhi *big.Int) (*big.Int, *big.Int) {
	c := []*big.Int{
		new(big.Int).Mul(alo, blo), new(big.Int).Mul(alo, bhi),
		new(big.Int).Mul(ahi, blo), new(big.Int).Mul(ahi, bhi),
	}
	lo, hi := c[0], c[0]
	for _, v := range c[1:] {
		if v.Cmp(lo) < 0 {
			lo = v
		}
		if v.Cmp(hi) > 0 {
			hi = v
		}
	}
	return lo, hi
}

func termRange(t term) (*big.Int, *big.Int) {
	lo, hi := big.NewInt(1), big.NewInt(1)
	for i, e := range t.factors {
		if i > 0 && e == t.factors[i-1] && len(t.factors) == 2 {
			m := absMax(e.vlo, e.vhi)
			sq := new(big.Int).Mul(m, m)
			if e.vlo.Sign() >= 0 {
				lo, hi = new(big.Int).Mul(e.vlo, e.vlo), new(big.Int).Mul(e.vhi, e.vhi)
			} else if e.vhi.Sign() <= 0 {
				lo, hi = new(big.Int).Mul(e.vhi, e.vhi), new(big.Int).Mul(e.vlo, e.vlo)
			} else {
				lo, hi = new(big.Int), sq
			}
			continue
		}
		lo, hi = intervalMul(lo, hi, e.vlo, e.vhi)
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

func (f *Field) Eval(terms ...Term) *Element {
	return f.newCheck(terms, true)
}

func (f *Field) AssertZero(terms ...Term) {
	f.newCheck(terms, false)
}

func (f *Field) newCheck(in []Term, withResult bool) *Element {
	return f.plainCheck(in, withResult)
}

func signed(v, q *big.Int) *big.Int {
	half := new(big.Int).Rsh(q, 1)
	if v.Cmp(half) > 0 {
		return new(big.Int).Sub(v, q)
	}
	return new(big.Int).Set(v)
}
