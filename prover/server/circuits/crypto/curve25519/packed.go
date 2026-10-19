package curve25519

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

// PackCoordinate combines already bounded limbs into native groups for a
// lookup row. The caller picks a group width whose packed value stays below
// the native modulus. The represented value is unchanged.
// Ben-Sasson, Chiesa, Genkin, Tromer, Virza, SNARKs for C, CRYPTO 2013, §2.3.3, https://cs-people.bu.edu/tromer/papers/csnark-20131007.pdf.
// Kosba, Papamanthou, Shi, xJsnark, IEEE S&P 2018, App. B-A(2), https://akosba.github.io/papers/xjsnark.pdf.
func PackCoordinate(api frontend.API, f *nonnative.Field, e *nonnative.Element, group int) []frontend.Variable {
	limbs := e.Limbs()
	limbBits := f.Layout().LimbBits
	var out []frontend.Variable
	for g := 0; g < len(limbs); g += group {
		sum := frontend.Variable(0)
		for j := g; j < min(g+group, len(limbs)); j++ {
			sum = api.Add(sum, api.Mul(limbs[j], Pow2(limbBits*(j-g))))
		}
		out = append(out, sum)
	}
	return out
}

// UnpackCoordinate records packed groups as sparse emulated limbs. The groups
// must come from a checked lookup or one-hot selection of bounded rows, since
// WithBounds only records that justification and adds no range constraints.
// Signed groups carry the symmetric interval of a negated reduced coordinate.
func UnpackCoordinate(f *nonnative.Field, packed []frontend.Variable, group int, signed bool) *nonnative.Element {
	widths := f.ReducedWidths()
	n := len(widths)
	limbs := make([]frontend.Variable, n)
	lo, hi := make([]*big.Int, n), make([]*big.Int, n)
	for j := range limbs {
		limbs[j] = 0
		lo[j], hi[j] = new(big.Int), new(big.Int)
		if j%group != 0 {
			continue
		}
		bits := 0
		for _, w := range widths[j:min(j+group, n)] {
			bits += w
		}
		limbs[j] = packed[j/group]
		hi[j].Sub(Pow2(bits), big.NewInt(1))
		if signed {
			lo[j].Neg(hi[j])
		}
	}
	return f.WithBounds(limbs, lo, hi)
}

// RowSplit chooses how many selector bits index rows of a packed constant
// table so that one-hot expansion plus row selection costs the fewest
// products. The inclusion-exclusion one-hot of k bits costs 2^k-k-1.
// Boyar, Find, Multiplicative Complexity of Vector Valued Boolean Functions, TCS 2018, §3.2, proof of Thm. 7, https://arxiv.org/abs/1407.6169.
func RowSplit(nbBits, nbLimbs int) int {
	columns := (nbLimbs+1)/2 + (nbLimbs+2)/3
	cost := func(k int) int {
		if k < 2 {
			return 0
		}
		return (1 << k) - k - 1
	}
	rowBits, best := 0, cost(nbBits)
	for k := 1; k <= nbBits; k++ {
		if c := cost(k) + cost(nbBits-k) + (1<<k)*columns; c < best {
			rowBits, best = k, c
		}
	}
	return rowBits
}

// SelectConstant selects one packed coordinate of a public table with
// one-hot row and column weights. Entry row+col*len(rows) is read through
// coordinate. Exclusive weights justify the packed bounds recorded with
// WithBounds. Those bounds are metadata, not range constraints.
// Boyar, Find, Multiplicative Complexity of Vector Valued Boolean Functions, TCS 2018, §3.2, proof of Thm. 7, https://arxiv.org/abs/1407.6169.
func SelectConstant(api frontend.API, f *nonnative.Field, rows, cols []frontend.Variable, group int, coordinate func(index int) *big.Int) *nonnative.Element {
	lay := f.Layout()
	fieldBits := f.Modulus().BitLen()
	limbs := make([]frontend.Variable, lay.NbLimbs)
	lo, hi := make([]*big.Int, lay.NbLimbs), make([]*big.Int, lay.NbLimbs)
	for i := range limbs {
		limbs[i] = 0
		lo[i] = new(big.Int)
		hi[i] = new(big.Int)
		if i%group != 0 {
			continue
		}
		width := min(group*lay.LimbBits, fieldBits-i*lay.LimbBits)
		mask := new(big.Int).Sub(Pow2(width), big.NewInt(1))
		value := frontend.Variable(0)
		for row, rf := range rows {
			inner := frontend.Variable(0)
			for col, cf := range cols {
				v := new(big.Int).Rsh(coordinate(row+col*len(rows)), uint(i*lay.LimbBits))
				v.And(v, mask)
				inner = api.Add(inner, api.Mul(cf, v))
			}
			value = api.Add(value, api.Mul(rf, inner))
		}
		limbs[i] = value
		hi[i] = mask
	}
	return f.WithBounds(limbs, lo, hi)
}
