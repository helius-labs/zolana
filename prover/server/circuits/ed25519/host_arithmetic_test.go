package ed25519

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
)

// Keep the original affine formulas as an independent oracle for the host
// witness optimizations. In particular this does not share the new batch
// inverse or extended-coordinate arithmetic.
func referenceHostAdd(p, q hostPoint) hostPoint {
	mod, d := Prime(), parameterD()
	rho := new(big.Int).Mul(p.x, q.x)
	rho.Mul(rho, p.y).Mul(rho, q.y).Mul(rho, d).Mod(rho, mod)
	nx := new(big.Int).Add(new(big.Int).Mul(p.x, q.y), new(big.Int).Mul(p.y, q.x))
	ny := new(big.Int).Add(new(big.Int).Mul(p.y, q.y), new(big.Int).Mul(p.x, q.x))
	divide := func(n, denominator *big.Int) *big.Int {
		inverse := new(big.Int).ModInverse(denominator, mod)
		if inverse == nil {
			return new(big.Int)
		}
		return new(big.Int).Mod(new(big.Int).Mul(n, inverse), mod)
	}
	return hostPoint{divide(nx, new(big.Int).Add(big.NewInt(1), rho)), divide(ny, new(big.Int).Sub(big.NewInt(1), rho))}
}
func referenceHostMul(p hostPoint, scalar *big.Int) hostPoint {
	out := hostPoint{new(big.Int), big.NewInt(1)}
	for i := scalar.BitLen() - 1; i >= 0; i-- {
		out = referenceHostAdd(out, out)
		if scalar.Bit(i) != 0 {
			out = referenceHostAdd(out, p)
		}
	}
	return out
}
func sameHostPoint(t *testing.T, got, want hostPoint) {
	t.Helper()
	if got.x.Cmp(want.x) != 0 || got.y.Cmp(want.y) != 0 {
		t.Fatalf("point mismatch: got (%s,%s), want (%s,%s)", got.x, got.y, want.x, want.y)
	}
}
func TestHostArithmeticDifferential(t *testing.T) {
	tx, _ := new(big.Int).SetString("14399317868200118260347934320527232580618823971194345261214217575416788799818", 10)
	ty, _ := new(big.Int).SetString("2707385501144840649318225287225658788936804267575313519463743609750303402022", 10)
	torsionGenerator := hostPoint{tx, ty}
	torsion := hostPoint{new(big.Int), big.NewInt(1)}
	scalars := []*big.Int{
		new(big.Int), big.NewInt(1), big.NewInt(2), big.NewInt(7), big.NewInt(8),
		new(big.Int).Sub(Order(), big.NewInt(1)), Order(), new(big.Int).Add(Order(), big.NewInt(1)),
		new(big.Int).Sub(pow2(256), big.NewInt(1)), new(big.Int).Add(pow2(511), big.NewInt(12345)),
	}
	random := rand.New(rand.NewSource(52937))
	for range 6 {
		scalars = append(scalars, new(big.Int).Rand(random, pow2(512)))
	}
	primeBases := []hostPoint{
		{new(big.Int), big.NewInt(1)}, generator(), referenceHostMul(generator(), big.NewInt(12345)),
	}
	points := []hostPoint{}
	for ti := 0; ti < 8; ti++ {
		for bi, base := range primeBases {
			p := referenceHostAdd(base, torsion)
			points = append(points, p)
			for si, scalar := range scalars {
				t.Run(fmt.Sprintf("torsion%d/base%d/scalar%d", ti, bi, si), func(t *testing.T) {
					px, py, scalarCopy := new(big.Int).Set(p.x), new(big.Int).Set(p.y), new(big.Int).Set(scalar)
					sameHostPoint(t, hostMul(p, scalar), referenceHostMul(p, scalar))
					if p.x.Cmp(px) != 0 || p.y.Cmp(py) != 0 || scalar.Cmp(scalarCopy) != 0 {
						t.Fatal("mutated caller's operands")
					}
				})
			}
		}
		torsion = referenceHostAdd(torsion, torsionGenerator)
	}
	for i, p := range points {
		// A field element may arrive through a noncanonical integer encoding.
		lifted := hostPoint{new(big.Int).Add(p.x, Prime()), new(big.Int).Sub(p.y, Prime())}
		for _, scalar := range []*big.Int{new(big.Int), big.NewInt(1), Order(), scalars[9]} {
			sameHostPoint(t, hostMul(lifted, scalar), referenceHostMul(p, scalar))
		}
		for j, q := range points {
			t.Run(fmt.Sprintf("add%d/%d", i, j), func(t *testing.T) { sameHostPoint(t, hostAdd(p, q), referenceHostAdd(p, q)) })
		}
	}
}
func TestHostArithmeticMalformedInputs(t *testing.T) {
	inverseD := new(big.Int).ModInverse(parameterD(), Prime())
	p := hostPoint{big.NewInt(1), big.NewInt(1)}
	// rho=+/-1 forces an affine denominator to zero. Both the original
	// independent divisions and the batch-inversion fallback remain total.
	points := []hostPoint{
		{big.NewInt(1), inverseD}, {big.NewInt(1), new(big.Int).Neg(inverseD)},
		{new(big.Int), new(big.Int)}, {big.NewInt(-3), new(big.Int).Add(Prime(), big.NewInt(7))},
	}
	for i, q := range points {
		t.Run(fmt.Sprintf("malformed%d", i), func(t *testing.T) {
			sameHostPoint(t, hostAdd(p, q), referenceHostAdd(p, q))
			for _, scalar := range []*big.Int{new(big.Int), big.NewInt(1), big.NewInt(2), Order()} {
				got := hostMul(q, scalar)
				if got.x == nil || got.y == nil || got.x.Sign() < 0 || got.y.Sign() < 0 || got.x.Cmp(Prime()) >= 0 || got.y.Cmp(Prime()) >= 0 {
					t.Fatal("invalid normalized hint result")
				}
			}
		})
	}
}
func BenchmarkHostMulExtended(b *testing.B) {
	p, s := generator(), Order()
	for b.Loop() {
		hostMul(p, s)
	}
}
func BenchmarkHostMulAffineReference(b *testing.B) {
	p, s := generator(), Order()
	for b.Loop() {
		referenceHostMul(p, s)
	}
}

func BenchmarkHostMulAffineBatched(b *testing.B) {
	p, s := generator(), Order()
	for b.Loop() {
		acc := hostPoint{new(big.Int), big.NewInt(1)}
		for i := s.BitLen() - 1; i >= 0; i-- {
			acc = hostAdd(acc, acc)
			if s.Bit(i) != 0 {
				acc = hostAdd(acc, p)
			}
		}
	}
}
