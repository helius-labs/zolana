package sha512

import (
	stdsha512 "crypto/sha512"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type sha512Circuit struct {
	Message []frontend.Variable
	Digest  [64]frontend.Variable `gnark:",public"`
}

func (c *sha512Circuit) Define(api frontend.API) error {
	d := Hash(api, c.Message)
	for i := range d {
		api.AssertIsEqual(d[i], c.Digest[i])
	}
	return nil
}
func TestSha512(t *testing.T) {
	for _, n := range []int{0, 3, 32, 64, 96, 111, 112, 128, 257} {
		t.Run(fmt.Sprintf("%dB", n), func(t *testing.T) {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &sha512Circuit{Message: make([]frontend.Variable, n)})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%d bytes: %d constraints", n, cs.GetNbConstraints())
			msg := make([]byte, n)
			w := &sha512Circuit{Message: make([]frontend.Variable, n)}
			for i := range msg {
				msg[i] = byte(17*i + 31)
				w.Message[i] = msg[i]
			}
			d := stdsha512.Sum512(msg)
			for i := range d {
				w.Digest[i] = d[i]
			}
			solve := func(opts ...solver.Option) error {
				wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
				if err != nil {
					return err
				}
				return cs.IsSolved(wit, opts...)
			}
			if err := solve(); err != nil {
				t.Fatal(err)
			}
			w.Digest[0] = d[0] ^ 1
			if solve() == nil {
				t.Fatal("wrong digest accepted")
			}
			w.Digest[0] = d[0]
			if n > 0 {
				w.Message[0] = 256
				if solve() == nil {
					t.Fatal("out-of-range byte accepted")
				}
				w.Message[0] = msg[0]
			}
			if n == 64 {
				called := false
				bad := func(q *big.Int, in, out []*big.Int) error {
					called = true
					if err := sha512ChunksHint(q, in, out); err != nil {
						return err
					}
					out[0].Add(out[0], big.NewInt(1))
					return nil
				}
				if solve(solver.OverrideHint(solver.GetHintID(sha512ChunksHint), bad)) == nil || !called {
					t.Fatal("forged chunks not rejected")
				}
				called = false
				badSlices := func(q *big.Int, in, out []*big.Int) error {
					called = true
					if err := sha512SlicesHint(q, in, out); err != nil {
						return err
					}
					out[0].Add(out[0], big.NewInt(1))
					return nil
				}
				if solve(solver.OverrideHint(solver.GetHintID(sha512SlicesHint), badSlices)) == nil || !called {
					t.Fatal("forged typed slices not rejected")
				}
			}
		})
	}
}

func TestSha512ConstantsFromPrimeRoots(t *testing.T) {
	var primes []int64
	for n := int64(2); len(primes) < 80; n++ {
		prime := true
		for d := int64(2); d*d <= n; d++ {
			if n%d == 0 {
				prime = false
				break
			}
		}
		if prime {
			primes = append(primes, n)
		}
	}
	cubeRoot := func(n *big.Int) *big.Int {
		low := new(big.Int)
		high := new(big.Int).Lsh(big.NewInt(1), uint((n.BitLen()+2)/3))
		for new(big.Int).Sub(high, low).Cmp(big.NewInt(1)) > 0 {
			mid := new(big.Int).Rsh(new(big.Int).Add(low, high), 1)
			cube := new(big.Int).Mul(mid, mid)
			cube.Mul(cube, mid)
			if cube.Cmp(n) <= 0 {
				low = mid
			} else {
				high = mid
			}
		}
		return low
	}
	for i, p := range primes {
		k := cubeRoot(new(big.Int).Lsh(big.NewInt(p), 192)).Uint64()
		if k != sha512K[i] {
			t.Fatalf("round constant %d", i)
		}
		if i < 8 {
			iv := new(big.Int).Sqrt(new(big.Int).Lsh(big.NewInt(p), 128)).Uint64()
			if iv != sha512IV[i] {
				t.Fatalf("IV %d", i)
			}
		}
	}
}

// This circuit deliberately exposes the claimed raw sum. The adversarial
// assignments below preserve its integer recomposition or its carry equation,
// so rejection specifically relies on each slice having its exact width.
type sha512SliceAdderCircuit struct{ A, B, Result frontend.Variable }

func (c *sha512SliceAdderCircuit) Define(api frontend.API) error {
	e := sha512New(api)
	e.rc.Check(c.A, 64)
	e.rc.Check(c.B, 64)
	out := e.add(sha512ScheduleWidths, c.A, c.B)
	api.AssertIsEqual(out.value, c.Result)
	return nil
}
func TestSha512TypedSlicesRejectOverflow(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &sha512SliceAdderCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name                  string
		a, b, honest, claimed *big.Int
		mutate                func([]*big.Int)
	}{
		{"one_bit_carry", big.NewInt(2), new(big.Int), big.NewInt(2), big.NewInt(2), func(out []*big.Int) { out[0].SetInt64(2); out[1].SetInt64(0) }},
		{"eight_bit_carry", sha512Pow(51), new(big.Int), sha512Pow(51), sha512Pow(51), func(out []*big.Int) { out[9].SetInt64(256); out[10].SetInt64(0) }},
		{"top_slice_carry", new(big.Int).Sub(sha512Pow(64), big.NewInt(1)), big.NewInt(1), new(big.Int), sha512Pow(64), func(out []*big.Int) { out[len(out)-1].SetInt64(8) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assignment := &sha512SliceAdderCircuit{tc.a, tc.b, tc.honest}
			honest, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(honest); err != nil {
				t.Fatal(err)
			}
			assignment.Result = tc.claimed
			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			called := false
			bad := func(q *big.Int, in, out []*big.Int) error {
				called = true
				if err := sha512SlicesHint(q, in, out); err != nil {
					return err
				}
				tc.mutate(out)
				return nil
			}
			if cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(sha512SlicesHint), bad)) == nil || !called {
				t.Fatal("out-of-range slice accepted or forged hint was not reached")
			}
		})
	}
}
