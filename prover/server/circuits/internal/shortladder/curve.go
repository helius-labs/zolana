// Package shortladder holds the short-Weierstrass model of Curve25519 that
// the X25519 checker and the Ed25519 verifier share: the A/3-shifted
// coefficients, variable-time host quotients, hint limb reconstruction, the
// packed distinct-coordinate guard and the packed constant-table selection.
// Each consumer keeps its own ladder step, scalar recoding and hint names.
package shortladder

import "math/big"

// MontgomeryA is the Montgomery coefficient of Curve25519.
const MontgomeryA = 486662

// Pow2 returns a public power of two for limb weights and compile-time bounds.
func Pow2(n int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(n)) }

// Prime returns a fresh copy of the base field modulus 2^255-19.
func Prime() *big.Int { return new(big.Int).Sub(Pow2(255), big.NewInt(19)) }

// Offset returns A/3 modulo p, the X translation that removes the quadratic
// term of the Montgomery equation.
func Offset() *big.Int { return ModRatio(Prime(), big.NewInt(MontgomeryA), big.NewInt(3)) }

// Coefficients returns the Weierstrass parameters of X=B(u+A/3) with
// a=B^2(1-A^2/3) and b=B^3(2A^3/27-A/3). B is one on Curve25519 and two on
// its quadratic twist.
func Coefficients(twist bool) (a, b *big.Int) {
	p := Prime()
	A := big.NewInt(MontgomeryA)
	a = new(big.Int).Mul(A, A)
	a.Mul(a, new(big.Int).ModInverse(big.NewInt(3), p))
	a.Sub(big.NewInt(1), a)
	b = new(big.Int).Exp(A, big.NewInt(3), p)
	b.Lsh(b, 1).Mul(b, new(big.Int).ModInverse(big.NewInt(27), p))
	b.Sub(b, Offset())
	if twist {
		a.Lsh(a, 2)
		b.Lsh(b, 3)
	}
	return a.Mod(a, p), b.Mod(b, p)
}

// ModRatio computes a variable-time host quotient modulo a prime. A zero
// denominator yields zero so witness generation stays total at exceptional
// inputs. Callers constrain every denominator they rely on.
func ModRatio(p, num, den *big.Int) *big.Int {
	d := new(big.Int).Mod(den, p)
	if d.Sign() == 0 {
		return new(big.Int)
	}
	d.ModInverse(d, p)
	return d.Mul(d, num).Mod(d, p)
}

// Integer recomposes unsigned little-endian hint limbs of the given radix.
func Integer(limbs []*big.Int, bits int) *big.Int {
	out := new(big.Int)
	for i := len(limbs) - 1; i >= 0; i-- {
		out.Lsh(out, uint(bits)).Add(out, limbs[i])
	}
	return out
}

// BalancedInteger recomposes signed hint limbs. A native residue above q/2
// stands for its negative, matching the balanced digit convention of HintBalanced.
func BalancedInteger(q *big.Int, limbs []*big.Int, bits int) *big.Int {
	half := new(big.Int).Rsh(q, 1)
	out := new(big.Int)
	for i := len(limbs) - 1; i >= 0; i-- {
		v := new(big.Int).Set(limbs[i])
		if v.Cmp(half) > 0 {
			v.Sub(v, q)
		}
		out.Lsh(out, uint(bits)).Add(out, v)
	}
	return out
}
