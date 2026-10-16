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

// Bounds absolute product coefficients by convolution of nonnegative bounds.
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

// Accumulates nonnegative coefficient bounds, extending the destination as needed.
func addInto(destination []*big.Int, source []*big.Int) []*big.Int {
	for len(destination) < len(source) {
		destination = append(destination, new(big.Int))
	}
	for i := range source {
		destination[i].Add(destination[i], source[i])
	}
	return destination
}

// Returns the smallest interval containing all products of two signed intervals.
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

// Propagates the trusted integer bounds of a polynomial term.
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

// Returns absolute per-limb bounds from the existing signed metadata.
func limbAbs(e *Element) []*big.Int {
	out := make([]*big.Int, len(e.limbs))
	for i := range out {
		out[i] = absMax(e.lo[i], e.hi[i])
	}
	return out
}

// lazyCoefficientIntervals bounds every polynomial coefficient of a Lazy sum.
func lazyCoefficientIntervals(terms []term) ([]*big.Int, []*big.Int) {
	lo, hi := factoredIntervals(terms)
	// Both representations are exact polynomial identities. Their interval
	// intersection preserves the smaller bound when expansion is less precise.
	expandedLo, expandedHi := factoredIntervals(expandedTerms(terms))
	for i := range lo {
		l, h := new(big.Int), new(big.Int)
		if i < len(expandedLo) {
			l, h = expandedLo[i], expandedHi[i]
		}
		lo[i], hi[i] = maxInt(lo[i], l), minInt(hi[i], h)
	}
	return lo, hi
}

// Bounds the factored polynomial without assuming cancellation between witnesses.
func factoredIntervals(terms []term) ([]*big.Int, []*big.Int) {
	var lo, hi []*big.Int
	for _, t := range terms {
		l, h := []*big.Int{new(big.Int).Set(t.coef)}, []*big.Int{new(big.Int).Set(t.coef)}
		for _, e := range t.factors {
			l, h = polyMulInterval(l, h, e.lo, e.hi)
		}
		lo, hi = addInto(lo, l), addInto(hi, h)
	}
	return lo, hi
}

// expandedTerms expands linear expressions and collects equal monomials.
// The native computation can keep its cheaper factored representation while
// interval arithmetic sees exact cancellations such as (a+b)^2-a^2.
func expandedTerms(terms []term) []term {
	for _, t := range terms {
		if len(t.factors) > 2 {
			return terms
		}
	}
	var leaves func(e *Element, coef *big.Int) []part
	leaves = func(e *Element, coef *big.Int) []part {
		if len(e.parts) == 0 {
			return []part{{coef: new(big.Int).Set(coef), e: e}}
		}
		var out []part
		for _, p := range e.parts {
			out = append(out, leaves(p.e, new(big.Int).Mul(coef, p.coef))...)
		}
		return out
	}
	// Nil slots distinguish constant, linear and quadratic terms. Keep
	// their first-seen order. Reversed quadratic keys name the same product.
	seen := map[[2]*Element]int{}
	var out []term
	add := func(key [2]*Element, coef *big.Int) {
		i, ok := seen[key]
		if !ok && key[1] != nil {
			i, ok = seen[[2]*Element{key[1], key[0]}]
		}
		if ok {
			out[i].coef.Add(out[i].coef, coef)
			return
		}
		seen[key] = len(out)
		t := term{coef: new(big.Int).Set(coef)}
		for _, e := range key {
			if e != nil {
				t.factors = append(t.factors, e)
			}
		}
		out = append(out, t)
	}
	for _, t := range terms {
		switch len(t.factors) {
		case 0:
			add([2]*Element{}, t.coef)
		case 1:
			for _, a := range leaves(t.factors[0], t.coef) {
				add([2]*Element{a.e, nil}, a.coef)
			}
		case 2:
			for _, a := range leaves(t.factors[0], t.coef) {
				for _, b := range leaves(t.factors[1], big.NewInt(1)) {
					add([2]*Element{a.e, b.e}, new(big.Int).Mul(a.coef, b.coef))
				}
			}
		}
	}
	nonzero := out[:0]
	for _, t := range out {
		if t.coef.Sign() != 0 {
			nonzero = append(nonzero, t)
		}
	}
	return nonzero
}

// Chooses a host signed representative modulo q for bounded hint arithmetic.
func signed(v, q *big.Int) *big.Int {
	half := new(big.Int).Rsh(q, 1)
	if v.Cmp(half) > 0 {
		return new(big.Int).Sub(v, q)
	}
	return new(big.Int).Set(v)
}
