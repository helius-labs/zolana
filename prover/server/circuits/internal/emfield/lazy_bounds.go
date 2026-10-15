package emfield

import "math/big"

func lazyBoundIntervals(terms []term) ([]*big.Int, []*big.Int) {
	intervals := func(ts []term) ([]*big.Int, []*big.Int) {
		var lo, hi []*big.Int
		for _, t := range ts {
			l, h := []*big.Int{new(big.Int).Set(t.coef)}, []*big.Int{new(big.Int).Set(t.coef)}
			for _, e := range t.factors {
				l, h = polyMulInterval(l, h, e.lo, e.hi)
			}
			lo, hi = addInto(lo, l), addInto(hi, h)
		}
		return lo, hi
	}
	lo, hi := intervals(terms)
	expandedLo, expandedHi := intervals(lazyBoundTerms(terms))
	// Both representations are exact polynomial identities. Their interval
	// intersection preserves the smaller bound when expansion is less precise.
	for i := range lo {
		l, h := new(big.Int), new(big.Int)
		if i < len(expandedLo) {
			l, h = expandedLo[i], expandedHi[i]
		}
		lo[i], hi[i] = maxInt(lo[i], l), minInt(hi[i], h)
	}
	return lo, hi
}

// lazyBoundTerms expands linear expressions and collects equal monomials.
// The native computation can keep its cheaper factored representation while
// interval arithmetic sees exact cancellations such as (a+b)^2-a^2.
func lazyBoundTerms(terms []term) []term {
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
	// their first-seen order; reversed quadratic keys name the same product.
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
