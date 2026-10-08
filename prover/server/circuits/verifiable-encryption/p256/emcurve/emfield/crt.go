package emfield

import (
	"math/big"
	"math/rand"
)

type poly []*big.Int

type crtBasis struct {
	forms   [][]*big.Int
	combine [][]*big.Int
}

func newCRTBasis(f poly, limbCount int, nativeModulus *big.Int, inverseVandermonde func(degree int) [][]*big.Int) *crtBasis {
	factors := factorSquarefree(f, nativeModulus)
	total := 0
	for _, g := range factors {
		total += 2*polyDeg(g) - 1
	}
	if total >= 2*limbCount-1 {
		return nil
	}
	basis := &crtBasis{combine: make([][]*big.Int, limbCount)}
	for j := range basis.combine {
		basis.combine[j] = make([]*big.Int, total)
		for k := range basis.combine[j] {
			basis.combine[j][k] = new(big.Int)
		}
	}
	offset := 0
	for _, g := range factors {
		factorDegree := polyDeg(g)
		residues := residueColumns(limbCount, g, nativeModulus)
		points := 2*factorDegree - 1
		for s := 0; s < points; s++ {
			x := big.NewInt(evalPoint(s))
			form := make([]*big.Int, limbCount)
			for i := range form {
				form[i] = new(big.Int)
				power := big.NewInt(1)
				for t := 0; t < factorDegree; t++ {
					form[i].Add(form[i], new(big.Int).Mul(power, residues[i][t]))
					power.Mul(power, x)
				}
				form[i].Mod(form[i], nativeModulus)
			}
			basis.forms = append(basis.forms, form)
		}
		cofactor, _ := polyDivMod(f, g, nativeModulus)
		inv := polyPowMod(cofactor, new(big.Int).Sub(new(big.Int).Exp(nativeModulus, big.NewInt(int64(factorDegree)), nil), big.NewInt(2)), g, nativeModulus)
		idempotent := polyMod(polyMul(cofactor, inv, nativeModulus), f, nativeModulus)
		interpolation := inverseVandermonde(points - 1)
		for c := 0; c < points; c++ {
			monomial := make(poly, c+1)
			for j := range monomial {
				monomial[j] = new(big.Int)
			}
			monomial[c].SetInt64(1)
			lifted := polyMod(polyMul(idempotent, polyMod(monomial, g, nativeModulus), nativeModulus), f, nativeModulus)
			for j := 0; j < limbCount && j < len(lifted); j++ {
				for s := 0; s < points; s++ {
					basis.combine[j][offset+s].Add(basis.combine[j][offset+s], new(big.Int).Mul(lifted[j], interpolation[c][s]))
				}
			}
		}
		offset += points
	}
	for j := range basis.combine {
		for k := range basis.combine[j] {
			basis.combine[j][k].Mod(basis.combine[j][k], nativeModulus)
		}
	}
	return basis
}

func (b *crtBasis) foldedProduct(x, y []*big.Int, q *big.Int) []*big.Int {
	w := make([]*big.Int, len(b.forms))
	for k, form := range b.forms {
		l, r := new(big.Int), new(big.Int)
		for i, c := range form {
			if i < len(x) {
				l.Add(l, new(big.Int).Mul(c, x[i]))
			}
			if i < len(y) {
				r.Add(r, new(big.Int).Mul(c, y[i]))
			}
		}
		w[k] = l.Mul(l, r).Mod(l, q)
	}
	out := make([]*big.Int, len(b.combine))
	for j, row := range b.combine {
		out[j] = new(big.Int)
		for k, c := range row {
			out[j].Add(out[j], new(big.Int).Mul(c, w[k]))
		}
		out[j].Mod(out[j], q)
	}
	return out
}

func residueColumns(coefficientCount int, g poly, q *big.Int) [][]*big.Int {
	factorDegree := polyDeg(g)
	columns := make([][]*big.Int, coefficientCount)
	for i := range columns {
		monomial := make(poly, i+1)
		for j := range monomial {
			monomial[j] = new(big.Int)
		}
		monomial[i].SetInt64(1)
		residue := polyMod(monomial, g, q)
		columns[i] = make([]*big.Int, factorDegree)
		for t := range columns[i] {
			columns[i][t] = new(big.Int)
			if t < len(residue) {
				columns[i][t].Set(residue[t])
			}
		}
	}
	return columns
}

func factorSquarefree(f poly, q *big.Int) []poly {
	var out []poly
	x := poly{new(big.Int), big.NewInt(1)}
	h := x
	rest := polyMonic(f, q)
	for d := 1; 2*d <= polyDeg(rest); d++ {
		h = polyPowMod(h, q, rest, q)
		g := polyGcd(rest, polySub(h, x, q), q)
		if polyDeg(g) > 0 {
			out = append(out, splitEqualDegree(g, d, q)...)
			rest, _ = polyDivMod(rest, g, q)
			rest = polyMonic(rest, q)
			h = polyMod(h, rest, q)
		}
	}
	if polyDeg(rest) > 0 {
		out = append(out, rest)
	}
	return out
}

func splitEqualDegree(g poly, d int, q *big.Int) []poly {
	if polyDeg(g) == d {
		return []poly{g}
	}
	e := new(big.Int).Exp(q, big.NewInt(int64(d)), nil)
	e.Sub(e, big.NewInt(1)).Rsh(e, 1)
	rng := rand.New(rand.NewSource(1))
	for {
		a := make(poly, polyDeg(g))
		for i := range a {
			a[i] = new(big.Int).Rand(rng, q)
		}
		b := polyPowMod(polyTrim(a), e, g, q)
		u := polyGcd(g, polySub(b, poly{big.NewInt(1)}, q), q)
		if k := polyDeg(u); k > 0 && k < polyDeg(g) {
			v, _ := polyDivMod(g, u, q)
			return append(splitEqualDegree(u, d, q), splitEqualDegree(polyMonic(v, q), d, q)...)
		}
	}
}

func polyTrim(a poly) poly {
	for len(a) > 0 && a[len(a)-1].Sign() == 0 {
		a = a[:len(a)-1]
	}
	return a
}

func polyDeg(a poly) int {
	return len(polyTrim(a)) - 1
}

func polyReduce(a poly, q *big.Int) poly {
	out := make(poly, len(a))
	for i, c := range a {
		out[i] = new(big.Int).Mod(c, q)
	}
	return polyTrim(out)
}

func polySub(a, b poly, q *big.Int) poly {
	n := max(len(a), len(b))
	out := make(poly, n)
	for i := range out {
		out[i] = new(big.Int)
		if i < len(a) {
			out[i].Add(out[i], a[i])
		}
		if i < len(b) {
			out[i].Sub(out[i], b[i])
		}
	}
	return polyReduce(out, q)
}

func polyMul(a, b poly, q *big.Int) poly {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	out := make(poly, len(a)+len(b)-1)
	for i := range out {
		out[i] = new(big.Int)
	}
	for i, x := range a {
		for j, y := range b {
			out[i+j].Add(out[i+j], new(big.Int).Mul(x, y))
		}
	}
	return polyReduce(out, q)
}

func polyDivMod(a, m poly, q *big.Int) (poly, poly) {
	remainder := polyReduce(a, q)
	m = polyTrim(m)
	inverseLeadingCoefficient := new(big.Int).ModInverse(m[len(m)-1], q)
	var quotient poly
	if len(remainder) >= len(m) {
		quotient = make(poly, len(remainder)-len(m)+1)
		for i := range quotient {
			quotient[i] = new(big.Int)
		}
	}
	for len(remainder) >= len(m) {
		c := new(big.Int).Mul(remainder[len(remainder)-1], inverseLeadingCoefficient)
		c.Mod(c, q)
		shift := len(remainder) - len(m)
		quotient[shift].Set(c)
		for i, mi := range m {
			remainder[shift+i].Sub(remainder[shift+i], new(big.Int).Mul(c, mi)).Mod(remainder[shift+i], q)
		}
		remainder = polyTrim(remainder)
	}
	return polyTrim(quotient), remainder
}

func polyMod(a, m poly, q *big.Int) poly {
	_, r := polyDivMod(a, m, q)
	return r
}

func polyPowMod(a poly, e *big.Int, m poly, q *big.Int) poly {
	result := poly{big.NewInt(1)}
	base := polyMod(a, m, q)
	for i := e.BitLen() - 1; i >= 0; i-- {
		result = polyMod(polyMul(result, result, q), m, q)
		if e.Bit(i) == 1 {
			result = polyMod(polyMul(result, base, q), m, q)
		}
	}
	return result
}

func polyMonic(a poly, q *big.Int) poly {
	a = polyTrim(a)
	inv := new(big.Int).ModInverse(a[len(a)-1], q)
	out := make(poly, len(a))
	for i, c := range a {
		out[i] = new(big.Int).Mul(c, inv)
		out[i].Mod(out[i], q)
	}
	return out
}

func polyGcd(a, b poly, q *big.Int) poly {
	a, b = polyReduce(a, q), polyReduce(b, q)
	for len(b) > 0 {
		a, b = b, polyMod(a, b, q)
	}
	return polyMonic(a, q)
}
