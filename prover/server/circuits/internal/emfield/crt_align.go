package emfield

import "math/big"

// For each X^2=d factor, use W=u*u', V=v*v', U=(u+B*v)*(u'+B*v').
// The full residue is real=W+d*V, imag=(U-W-B^2*V)/B. Native radix
// evaluation and every even prefix use only V and U, so projected checks
// share six products with any later full nine-product multiplication. The
// square kernel was built before this basis change.
func (b *crtBasis) alignQuadraticProducts(radix, q *big.Int) {
	if !b.quadratic {
		return
	}
	oldForms, oldCombine := b.forms, b.combine
	b.forms = make([][]*big.Int, len(oldForms))
	b.combine = make([][]*big.Int, len(oldCombine))
	for j := range b.combine {
		b.combine[j] = make([]*big.Int, len(oldCombine[j]))
	}
	inv := new(big.Int).ModInverse(radix, q)
	mod := func(v *big.Int) *big.Int { return new(big.Int).Mod(v, q) }
	for k := 0; k < len(oldForms); k += 3 {
		b.forms[k] = oldForms[k]
		b.forms[k+1] = make([]*big.Int, len(oldForms[k]))
		for i := range b.forms[k+1] {
			b.forms[k+1][i] = mod(new(big.Int).Sub(oldForms[k+1][i], oldForms[k][i]))
		}
		b.forms[k+2] = make([]*big.Int, len(oldForms[k]))
		for i := range oldForms[k] {
			b.forms[k+2][i] = mod(new(big.Int).Add(b.forms[k][i], new(big.Int).Mul(radix, b.forms[k+1][i])))
		}
		for j := range b.combine {
			row := oldCombine[j]
			alpha := new(big.Int).Add(new(big.Int).Add(row[k], row[k+1]), row[k+2])
			beta := new(big.Int).Sub(row[k+1], row[k+2])
			delta := new(big.Int).Add(row[k+1], row[k+2])
			betaOverB := mod(new(big.Int).Mul(beta, inv))
			b.combine[j][k] = mod(new(big.Int).Sub(alpha, betaOverB))
			b.combine[j][k+1] = mod(new(big.Int).Sub(delta, new(big.Int).Mul(radix, beta)))
			b.combine[j][k+2] = betaOverB
		}
	}
	// Certify every coefficient of the complete bilinear tensor over Fq,
	// independent of any later prefix choice or input range assumptions.
	n := len(b.combine)
	for out := 0; out < n; out++ {
		for i := 0; i < n; i++ {
			for j := 0; j < n; j++ {
				before, after := new(big.Int), new(big.Int)
				for k := range b.forms {
					before.Add(before, new(big.Int).Mul(oldCombine[out][k], new(big.Int).Mul(oldForms[k][i], oldForms[k][j])))
					after.Add(after, new(big.Int).Mul(b.combine[out][k], new(big.Int).Mul(b.forms[k][i], b.forms[k][j])))
				}
				if mod(new(big.Int).Sub(before, after)).Sign() != 0 {
					panic("aligned CRT product tensor mismatch")
				}
			}
		}
	}
}
