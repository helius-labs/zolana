package emfield

import "math/big"

// For g=z^2+g1*z+g0, beta=z+g1/2 satisfies beta^2=d=g1^2/4-g0.
// The square of a+b*beta follows from two base-field products:
// u=a*b, v=(a+b)*(a+d*b), square=v-(1+d)*u+2*u*beta.
func (b *crtBasis) appendQuadraticSquare(f, g, idem poly, n int, q *big.Int) {
	half := new(big.Int).ModInverse(big.NewInt(2), q)
	shift := new(big.Int).Mod(new(big.Int).Mul(g[1], half), q)
	d := new(big.Int).Sub(new(big.Int).Mul(shift, shift), g[0])
	d.Mod(d, q)
	res := residueColumns(n, g, q)
	a, bb := make([]*big.Int, n), make([]*big.Int, n)
	ab, adb := make([]*big.Int, n), make([]*big.Int, n)
	for i := range a {
		bb[i] = new(big.Int).Set(res[i][1])
		a[i] = new(big.Int).Sub(res[i][0], new(big.Int).Mul(shift, bb[i]))
		a[i].Mod(a[i], q)
		ab[i] = new(big.Int).Add(a[i], bb[i])
		adb[i] = new(big.Int).Add(a[i], new(big.Int).Mul(d, bb[i]))
		ab[i].Mod(ab[i], q)
		adb[i].Mod(adb[i], q)
	}
	b.squareLeft = append(b.squareLeft, a, ab)
	b.squareRight = append(b.squareRight, bb, adb)
	u := poly{new(big.Int).Sub(g[1], new(big.Int).Add(big.NewInt(1), d)), big.NewInt(2)}
	u = polyMod(polyMul(idem, u, q), f, q)
	for j := range b.squareCombine {
		left, right := new(big.Int), new(big.Int)
		if j < len(u) {
			left.Set(u[j])
		}
		if j < len(idem) {
			right.Set(idem[j])
		}
		b.squareCombine[j] = append(b.squareCombine[j], left, right)
	}
}
