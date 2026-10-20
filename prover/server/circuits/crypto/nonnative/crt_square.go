package nonnative

import "math/big"

// With beta=z+g1/2 and beta^2=d, (a+b*beta)^2=v-(1+d)u+2u*beta for the two
// products u=a*b and v=(a+b)(a+d*b).
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

// certifySquares checks the symmetric square tensor, which fixes 2*X^(i+l) mod f
// for every limb pair including i=l.
func (b *crtBasis) certifySquares(powers [][]*big.Int, q *big.Int) {
	n := len(b.squareCombine)
	for i := 0; i < n; i++ {
		for l := 0; l < n; l++ {
			for j := 0; j < n; j++ {
				sum := new(big.Int).Neg(new(big.Int).Lsh(powers[i+l][j], 1))
				for k, left := range b.squareLeft {
					pair := new(big.Int).Mul(left[i], b.squareRight[k][l])
					pair.Add(pair, new(big.Int).Mul(left[l], b.squareRight[k][i]))
					sum.Add(sum, pair.Mul(pair, b.squareCombine[j][k]))
				}
				if sum.Mod(sum, q).Sign() != 0 {
					panic("CRT square tensor mismatch")
				}
			}
		}
	}
}
