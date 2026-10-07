package hosttest

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/prover-test/hintattack"
)

const (
	maxSmallCoordinate = 1 << 8
	byteRadix          = 256
)

type RangeCheckProver struct {
	Name    string
	Options []solver.Option
}

func RangeCheckProvers(t testing.TB) []RangeCheckProver {
	t.Helper()
	skip := hintattack.SkipMissingLookupQueries(t)
	return []RangeCheckProver{
		{"honest range check decomposition", []solver.Option{skip}},
		{"range check decomposition with an unreduced top limb", []solver.Option{skip, solver.OverrideHint(solver.GetHintID(rangecheck.DecomposeHint), unreducedTopLimb)}},
	}
}

func unreducedTopLimb(mod *big.Int, inputs, outputs []*big.Int) error {
	if err := rangecheck.DecomposeHint(mod, inputs, outputs); err != nil || len(outputs) == 0 {
		return err
	}
	top := len(outputs) - 1
	outputs[top].Rsh(inputs[2], uint(inputs[1].Uint64())*uint(top))
	return nil
}

func CarryIntoByte(t testing.TB, bytes []frontend.Variable, k int) {
	t.Helper()
	if k < 1 || k >= len(bytes) {
		t.Fatalf("carry into byte %d of %d", k, len(bytes))
	}
	high, low := byteAssignment(t, bytes[k-1]), byteAssignment(t, bytes[k])
	if high == 0 {
		t.Fatalf("byte %d is zero and cannot lend 256 to byte %d", k-1, k)
	}
	bytes[k-1], bytes[k] = high-1, low+byteRadix
}

func byteAssignment(t testing.TB, v frontend.Variable) int {
	t.Helper()
	switch b := v.(type) {
	case byte:
		return int(b)
	case int:
		return b
	}
	t.Fatalf("byte assignment of type %T", v)
	return 0
}

func UncompressedPoint(x, y *big.Int) [65]byte {
	var out [65]byte
	out[0] = 0x04
	x.FillBytes(out[1:33])
	y.FillBytes(out[33:65])
	return out
}

func SharedX(t testing.TB, ephemeral *ecdh.PrivateKey, recipient [65]byte) []byte {
	t.Helper()
	public, err := ecdh.P256().NewPublicKey(recipient[:])
	if err != nil {
		t.Fatalf("recipient: %v", err)
	}
	shared, err := ephemeral.ECDH(public)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return shared
}

type NonCanonicalRecipient struct {
	Name      string
	Canonical [65]byte
	Presented [65]byte
}

func NonCanonicalRecipients(t testing.TB) []NonCanonicalRecipient {
	t.Helper()
	p := elliptic.P256().Params().P
	smallX, smallXY := smallXPoint()
	smallYX, smallY := smallYPoint()
	shiftedX, shiftedY := new(big.Int).Add(smallX, p), new(big.Int).Add(smallY, p)
	if shiftedX.BitLen() > 256 || shiftedY.BitLen() > 256 {
		t.Fatal("a coordinate plus the modulus does not fit 32 bytes")
	}
	return []NonCanonicalRecipient{
		{"x plus modulus", UncompressedPoint(smallX, smallXY), UncompressedPoint(shiftedX, smallXY)},
		{"y plus modulus", UncompressedPoint(smallYX, smallY), UncompressedPoint(smallYX, shiftedY)},
	}
}

func smallXPoint() (x, y *big.Int) {
	p := elliptic.P256().Params().P
	for i := int64(1); i < maxSmallCoordinate; i++ {
		x := big.NewInt(i)
		if y := new(big.Int).ModSqrt(curveRHS(x), p); y != nil {
			return x, y
		}
	}
	panic(fmt.Sprintf("hosttest: no P-256 point with x below %d", maxSmallCoordinate))
}

func smallYPoint() (x, y *big.Int) {
	params := elliptic.P256().Params()
	for i := int64(1); i < maxSmallCoordinate; i++ {
		y := big.NewInt(i)
		c := new(big.Int).Sub(params.B, new(big.Int).Mul(y, y))
		c.Mod(c, params.P)
		if x := singleCubicRoot(c, params.P); x != nil {
			return x, y
		}
	}
	panic(fmt.Sprintf("hosttest: no P-256 point with y below %d", maxSmallCoordinate))
}

func curveRHS(x *big.Int) *big.Int {
	params := elliptic.P256().Params()
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x).Sub(rhs, new(big.Int).Mul(big.NewInt(3), x)).Add(rhs, params.B)
	return rhs.Mod(rhs, params.P)
}

func singleCubicRoot(c, p *big.Int) *big.Int {
	cubic := []*big.Int{new(big.Int).Set(c), new(big.Int).Sub(p, big.NewInt(3)), big.NewInt(0), big.NewInt(1)}
	power := []*big.Int{big.NewInt(1), big.NewInt(0), big.NewInt(0)}
	for i := p.BitLen() - 1; i >= 0; i-- {
		power = cubicMulMod(power, power, c, p)
		if p.Bit(i) == 1 {
			power = cubicMulMod(power, []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(0)}, c, p)
		}
	}
	power[1].Sub(power[1], big.NewInt(1)).Mod(power[1], p)
	g := polyGCD(cubic, trimPoly(power), p)
	if len(g) != 2 {
		return nil
	}
	root := new(big.Int).ModInverse(g[1], p)
	root.Mul(root, g[0]).Neg(root).Mod(root, p)
	return root
}

func cubicMulMod(a, b []*big.Int, c, p *big.Int) []*big.Int {
	prod := make([]*big.Int, 5)
	for i := range prod {
		prod[i] = new(big.Int)
	}
	for i, ai := range a {
		for j, bj := range b {
			prod[i+j].Add(prod[i+j], new(big.Int).Mul(ai, bj))
		}
	}
	for d := 4; d >= 3; d-- {
		lead := prod[d]
		prod[d-2].Add(prod[d-2], new(big.Int).Mul(big.NewInt(3), lead))
		prod[d-3].Sub(prod[d-3], new(big.Int).Mul(c, lead))
	}
	out := prod[:3]
	for _, v := range out {
		v.Mod(v, p)
	}
	return out
}

func trimPoly(a []*big.Int) []*big.Int {
	n := len(a)
	for n > 0 && a[n-1].Sign() == 0 {
		n--
	}
	return a[:n]
}

func polyRem(a, b []*big.Int, p *big.Int) []*big.Int {
	rem := make([]*big.Int, len(a))
	for i, v := range a {
		rem[i] = new(big.Int).Set(v)
	}
	rem = trimPoly(rem)
	leadInverse := new(big.Int).ModInverse(b[len(b)-1], p)
	for len(rem) >= len(b) {
		factor := new(big.Int).Mul(rem[len(rem)-1], leadInverse)
		shift := len(rem) - len(b)
		for i, bi := range b {
			rem[shift+i].Sub(rem[shift+i], new(big.Int).Mul(factor, bi)).Mod(rem[shift+i], p)
		}
		rem = trimPoly(rem)
	}
	return rem
}

func polyGCD(a, b []*big.Int, p *big.Int) []*big.Int {
	a, b = trimPoly(a), trimPoly(b)
	for len(b) > 0 {
		a, b = b, polyRem(a, b, p)
	}
	return a
}
