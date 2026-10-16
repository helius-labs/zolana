package shortchecker

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

func hostTestPoint(twist bool) hostPoint {
	u := big.NewInt(9)
	if twist {
		u.SetInt64(2)
	}
	p := prime()
	rhs := new(big.Int).Mul(u, u)
	rhs.Add(rhs, new(big.Int).Mul(big.NewInt(486662), u)).Add(rhs, big.NewInt(1)).Mul(rhs, u)
	if twist {
		rhs.Lsh(rhs, 3)
	}
	rhs.Mod(rhs, p)
	y := new(big.Int).ModSqrt(rhs, p)
	x := new(big.Int).Add(u, offset())
	if twist {
		x.Lsh(x, 1)
	}
	x.Mod(x, p)
	return hostPoint{x, y}
}
func sameHostPoint(p, q hostPoint) bool {
	if p.x == nil || q.x == nil {
		return p.x == nil && q.x == nil
	}
	return p.x.Cmp(q.x) == 0 && p.y.Cmp(q.y) == 0
}
func TestHostJacobianMatchesAffine(t *testing.T) {
	for _, twist := range []bool{false, true} {
		a, _ := coefficients(twist)
		p := hostTestPoint(twist)
		n := order(twist)
		torsionX := offset()
		if twist {
			torsionX.Lsh(torsionX, 1).Mod(torsionX, prime())
		}
		points := []hostPoint{p, {}, {torsionX, new(big.Int)}, {big.NewInt(1), big.NewInt(2)},
			// Deliberately off-curve points exercise maximal field products
			// and subtraction boundaries against the independent affine path.
			{new(big.Int).Sub(prime(), big.NewInt(1)), new(big.Int).Sub(prime(), big.NewInt(1))},
			{new(big.Int).Sub(prime(), big.NewInt(1)), big.NewInt(1)},
			{new(big.Int), big.NewInt(1)},
		}
		scalars := []*big.Int{new(big.Int), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5), big.NewInt(17), new(big.Int).Sub(n, big.NewInt(1)), n, new(big.Int).Add(n, big.NewInt(1)), new(big.Int).Lsh(n, 1)}
		for i := 0; i < 32; i++ {
			seed := sha256.Sum256([]byte(fmt.Sprintf("host differential %t %d", twist, i)))
			scalars = append(scalars, new(big.Int).SetBytes(seed[:]))
		}
		for i, point := range points {
			for _, s := range scalars {
				want := hostMulAffine(point, s, a)
				got := hostMul(point, s, a)
				if !sameHostPoint(want, got) {
					t.Fatalf("twist%t point%d scalar%s: jacobian differs from affine", twist, i, s)
				}
			}
		}
	}
}

var hostBenchmarkResult hostPoint

func BenchmarkHostMul(b *testing.B) {
	for _, twist := range []bool{false, true} {
		a, _ := coefficients(twist)
		p := hostTestPoint(twist)
		seed := sha256.Sum256([]byte("representative X25519 host scalar"))
		scalar := new(big.Int).SetBytes(seed[:])
		scalar.Mod(scalar, order(twist))
		for _, version := range []struct {
			name string
			fn   func(hostPoint, *big.Int, *big.Int) hostPoint
		}{{"affine", hostMulAffine}, {"jacobian", hostMul}} {
			b.Run(fmt.Sprintf("twist%t/%s", twist, version.name), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					hostBenchmarkResult = version.fn(p, scalar, a)
				}
			})
		}
	}
}
