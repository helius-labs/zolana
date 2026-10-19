package x25519

import (
	nativeecdh "crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

type hostileCircuit struct {
	Scalar, Peer, Shared [32]frontend.Variable
	Layout               nonnative.Layout `gnark:"-"`
}

func (w *hostileCircuit) Define(api frontend.API) error {
	lay := w.Layout
	f := nonnative.NewFor(api, prime(), lay)
	var k, ub, sb []frontend.Variable
	for i := 0; i < 32; i++ {
		k = append(k, api.ToBinary(w.Scalar[i], 8)...)
		ub = append(ub, api.ToBinary(w.Peer[i], 8)...)
		sb = append(sb, api.ToBinary(w.Shared[i], 8)...)
	}
	limbs := func(bits []frontend.Variable) *nonnative.Element {
		ls := make([]frontend.Variable, lay.NbLimbs)
		widths := f.ReducedWidths()
		for i, v := range widths {
			ls[i] = api.FromBinary(bits[i*lay.LimbBits : i*lay.LimbBits+v]...)
		}
		return f.Bounded(ls, widths)
	}
	r := multiply(api, f, limbs(ub), k)
	f.AssertZero(term(1, r), term(-1, limbs(sb)))
	return nil
}
func hostileCompile(t *testing.T, lay nonnative.Layout) constraint.ConstraintSystem {
	t.Helper()
	cs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &hostileCircuit{Layout: lay})
	if e != nil {
		t.Fatal(e)
	}
	return cs
}
func hostileDecode(s string) []byte {
	v, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return v
}
func hostileBytes(n *big.Int) []byte { v := n.FillBytes(make([]byte, 32)); slices.Reverse(v); return v }
func hostileInt(v []byte) *big.Int {
	v = slices.Clone(v)
	slices.Reverse(v)
	return new(big.Int).SetBytes(v)
}
func hostileWitness(t *testing.T, k, peer []byte) *hostileCircuit {
	t.Helper()
	sk, e := nativeecdh.X25519().NewPrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := nativeecdh.X25519().NewPublicKey(peer)
	if e != nil {
		t.Fatal(e)
	}
	r, e := sk.ECDH(pk)
	if e != nil {
		t.Fatal(e)
	}
	w := new(hostileCircuit)
	for i := 0; i < 32; i++ {
		w.Scalar[i], w.Peer[i], w.Shared[i] = k[i], peer[i], r[i]
	}
	return w
}
func hostileSolve(t *testing.T, cs constraint.ConstraintSystem, w *hostileCircuit, opts ...solver.Option) error {
	t.Helper()
	wit, e := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if e != nil {
		t.Fatal(e)
	}
	return cs.IsSolved(wit, opts...)
}
func hostileReject(t *testing.T, cs constraint.ConstraintSystem, w *hostileCircuit, fn, bad solver.Hint, others ...solver.Option) {
	t.Helper()
	called := false
	replacement := func(q *big.Int, in, out []*big.Int) error { called = true; return bad(q, in, out) }
	e := hostileSolve(t, cs, w, append(others, solver.OverrideHint(solver.GetHintID(fn), replacement))...)
	if !called {
		t.Fatal("forged hint not called")
	}
	if e == nil {
		t.Fatal("accepted forged hint")
	}
	if !strings.Contains(e.Error(), "is not satisfied") {
		t.Fatalf("expected constraint rejection, got %v", e)
	}
}
func hostileZero(_ *big.Int, _, out []*big.Int) error {
	for _, o := range out {
		o.SetInt64(0)
	}
	return nil
}
func hostileFlip(fn solver.Hint, index int) solver.Hint {
	return func(q *big.Int, in, out []*big.Int) error {
		if e := fn(q, in, out); e != nil {
			return e
		}
		out[index].Xor(out[index], big.NewInt(1))
		return nil
	}
}

func TestShortCheckerAdversarialHints(t *testing.T) {
	for _, lay := range []nonnative.Layout{{NbLimbs: 7, LimbBits: 37, PieceBits: 10}, nonnative.Layout{NbLimbs: 8, LimbBits: 32, PieceBits: 11}} {
		t.Run(fmt.Sprint(lay.LimbBits), func(t *testing.T) { runTestShortCheckerAdversarialHints(t, lay) })
	}
}
func runTestShortCheckerAdversarialHints(t *testing.T, lay nonnative.Layout) {
	cs := hostileCompile(t, lay)
	scalar := sha256.Sum256([]byte("independent short-checker hostile hints"))
	for _, u := range []int64{2, 9} {
		peer := hostileBytes(big.NewInt(u))
		w := hostileWitness(t, scalar[:], peer)
		if e := hostileSolve(t, cs, w); e != nil {
			t.Fatal(e)
		}
		for _, row := range []struct {
			name    string
			fn, bad solver.Hint
		}{
			{"offcurve result", shortScalarMulHint, hostileFlip(shortScalarMulHint, 0)},
			{"subgroup root", rootHint, hostileFlip(rootHint, 0)},
			{"lift y", liftHint, hostileFlip(liftHint, 0)},
			{"u conversion", montUHint, hostileFlip(montUHint, 0)},
			{"doubling result", xDoubleHint, hostileFlip(xDoubleHint, 0)},
			{"doubling helper", xDoubleHint, func(q *big.Int, in, out []*big.Int) error {
				if e := xDoubleHint(q, in, out); e != nil {
					return e
				}
				out[len(out)/2].Xor(out[len(out)/2], big.NewInt(1))
				return nil
			}},
			{"zero decomposition", shortDecomposeScalarHint, hostileZero},
			{"wrong scalar modulus", shortDecomposeScalarHint, func(q *big.Int, in, out []*big.Int) error {
				other := append([]*big.Int{}, in...)
				other[0] = new(big.Int).Sub(big.NewInt(1), in[0])
				return shortDecomposeScalarHint(q, other, out)
			}},
			{"decomposition bit", shortDecomposeScalarHint, hostileFlip(shortDecomposeScalarHint, 20)},
			{"decomposition sign", shortDecomposeScalarHint, func(q *big.Int, in, out []*big.Int) error {
				if e := shortDecomposeScalarHint(q, in, out); e != nil {
					return e
				}
				out[0].SetInt64(2)
				return nil
			}},
		} {
			t.Run(fmt.Sprintf("u%d/%s", u, row.name), func(t *testing.T) { hostileReject(t, cs, w, row.fn, row.bad) })
		}

		t.Run(fmt.Sprintf("u%d/consistent_wrong_scalar", u), func(t *testing.T) {
			badK := slices.Clone(scalar[:])
			badK[0] &= 248
			badK[31] &= 127
			badK[31] |= 64
			badK = hostileBytes(new(big.Int).Add(hostileInt(badK), big.NewInt(8)))
			forgedWitness := *w
			forgedWitness.Shared = hostileWitness(t, badK, peer).Shared
			changedDecomposition := func(q *big.Int, in, out []*big.Int) error {
				changed := append([]*big.Int{}, in...)
				changed[2] = new(big.Int).Add(changed[2], big.NewInt(1))
				return shortDecomposeScalarHint(q, changed, out)
			}
			changedResult := func(q *big.Int, in, out []*big.Int) error {
				return nonnative.Unwrap(q, in, out, func(_ *big.Int, n, v, o []*big.Int) error {
					a, _ := coefficients(n[0].Sign() != 0)
					r := hostMul(hostPoint{v[0], v[1]}, new(big.Int).Add(v[2], big.NewInt(1)), a)
					o[0].Set(r.x)
					o[1].Set(r.y)
					return nil
				})
			}
			// With the original decomposition, only the final target equality
			// binds this otherwise valid prime-subgroup result to the scalar.
			hostileReject(t, cs, &forgedWitness, shortScalarMulHint, changedResult)
			hostileReject(t, cs, &forgedWitness, shortDecomposeScalarHint, changedDecomposition, solver.OverrideHint(solver.GetHintID(shortScalarMulHint), changedResult))
		})

		for _, v := range []int64{u / 9, 2} {
			t.Run(fmt.Sprintf("u%d/class%d", u, v), func(t *testing.T) {
				hostileReject(t, cs, w, curveClassHint, func(_ *big.Int, _, out []*big.Int) error { out[0].SetInt64(v); return nil }, solver.OverrideHint(solver.GetHintID(liftHint), func(q *big.Int, in, out []*big.Int) error { hostileZero(q, in, out); out[0].SetInt64(1); return nil }))
			})
		}
	}
}

// The fake result is R+(0,0), whose Montgomery u-coordinate is 1/u(R).
// These scalars have an even short-relation denominator. Without subgroup
// membership this forgery satisfies the entire prime-order short relation.
func TestShortCheckerRejectsTorsionShift(t *testing.T) {
	for _, lay := range []nonnative.Layout{{NbLimbs: 7, LimbBits: 37, PieceBits: 10}, nonnative.Layout{NbLimbs: 8, LimbBits: 32, PieceBits: 11}} {
		t.Run(fmt.Sprint(lay.LimbBits), func(t *testing.T) { runTestShortCheckerRejectsTorsionShift(t, lay) })
	}
}
func runTestShortCheckerRejectsTorsionShift(t *testing.T, lay nonnative.Layout) {
	cs := hostileCompile(t, lay)
	for _, row := range []struct {
		u int64
		k string
	}{
		{9, "b89d5e162cd613ae3dae5984c75caf1ddbec674f6b40ddb8ed9979673d52177b"},
		{2, "189ed82f308915f88dc6ad8a7450523962979815d4c8f8659d7d8aad8ce13c70"},
	} {
		t.Run(fmt.Sprint(row.u), func(t *testing.T) {
			w := hostileWitness(t, hostileDecode(row.k), hostileBytes(big.NewInt(row.u)))
			if e := hostileSolve(t, cs, w); e != nil {
				t.Fatal(e)
			}
			raw := make([]byte, 32)
			for i, v := range w.Shared {
				raw[i] = v.(byte)
			}
			fake := hostileBytes(new(big.Int).ModInverse(hostileInt(raw), prime()))
			for i, v := range fake {
				w.Shared[i] = v
			}
			forged := func(q *big.Int, in, out []*big.Int) error {
				return nonnative.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
					twist := n[0].Sign() != 0
					a, _ := coefficients(twist)
					r := hostMul(hostPoint{v[0], v[1]}, v[2], a)
					tx := offset()
					if twist {
						tx.Lsh(tx, 1).Mod(tx, p)
					}
					r = hostAdd(r, hostPoint{tx, new(big.Int)}, a)
					o[0].Set(r.x)
					o[1].Set(r.y)
					return nil
				})
			}
			hostileReject(t, cs, w, shortScalarMulHint, forged)
		})
	}
}
