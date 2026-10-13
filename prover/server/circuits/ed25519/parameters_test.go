package ed25519

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestCurveParameters(t *testing.T) {
	p, l, d := Prime(), Order(), parameterD()
	if !p.ProbablyPrime(64) || !l.ProbablyPrime(64) {
		t.Fatal("coordinate and scalar moduli must be prime")
	}
	if new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(d, big.NewInt(121666)), big.NewInt(121665)), p).Sign() != 0 || big.Jacobi(d, p) != -1 {
		t.Fatal("invalid complete Edwards parameter")
	}
	onCurve := func(q hostPoint) {
		t.Helper()
		x2 := new(big.Int).Mul(q.x, q.x)
		y2 := new(big.Int).Mul(q.y, q.y)
		f := new(big.Int).Sub(y2, x2)
		f.Sub(f, big.NewInt(1)).Sub(f, new(big.Int).Mul(d, new(big.Int).Mul(x2, y2))).Mod(f, p)
		if f.Sign() != 0 {
			t.Fatal("constant point is off curve")
		}
	}
	b := generator()
	onCurve(b)
	var compressed [32]byte
	for i := range compressed {
		compressed[i] = byte(new(big.Int).Rsh(b.y, uint(8*i)).Uint64())
	}
	compressed[31] |= byte(b.x.Bit(0)) << 7
	if hex.EncodeToString(compressed[:]) != "5866666666666666666666666666666666666666666666666666666666666666" || hostIdentity(b) || !hostIdentity(hostMul(b, l)) {
		t.Fatal("basepoint encoding or prime order is incorrect")
	}
	table := torsionTable()
	seen := make(map[string]bool)
	for _, q := range table {
		onCurve(q)
		key := q.x.String() + "," + q.y.String()
		if seen[key] || !hostIdentity(hostMul(q, big.NewInt(8))) {
			t.Fatal("torsion table is not the eight distinct points of order dividing eight")
		}
		seen[key] = true
	}
	if hostIdentity(hostMul(table[1], big.NewInt(4))) {
		t.Fatal("torsion generator must have exact order eight")
	}
	if new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(montScale, montScale), big.NewInt(486664)), p).Sign() != 0 {
		t.Fatal("invalid Edwards-to-Weierstrass scaling")
	}
	// Check the transformed constants against the cubic independently of
	// the circuit's multiplication certificates.
	mb := new(big.Int).Sub(new(big.Int).Mul(big.NewInt(2), new(big.Int).Exp(montOffset, big.NewInt(3), p)), montOffset)
	for i := int64(1); i <= 16; i++ {
		q := hostMont(hostMul(b, big.NewInt(i)))
		f := new(big.Int).Mul(q.y, q.y)
		f.Sub(f, new(big.Int).Exp(q.x, big.NewInt(3), p)).Sub(f, new(big.Int).Mul(montA, q.x)).Sub(f, mb).Mod(f, p)
		if f.Sign() != 0 {
			t.Fatal("transformed constant point is off the Weierstrass curve")
		}
	}
}
