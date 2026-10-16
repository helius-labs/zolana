package shortchecker

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/internal/emfield"
	"math/big"
	"testing"
)

type distinctCircuit struct{ A, B [7]frontend.Variable }

func (c *distinctCircuit) Define(api frontend.API) error {
	lay := emfield.Layout{NbLimbs: 7, LimbBits: 37, PieceBits: 10, Lookups: true}
	f := emfield.NewFor(api, prime(), lay)
	cv := &curve{api: api, lay: lay, fp: f}
	cv.assertDistinctX(f.FromLimbs(c.A[:]), f.FromLimbs(c.B[:]))
	return nil
}
func TestDistinctAliases(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &distinctCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	p, q := prime(), ecc.BN254.ScalarField()
	vs := []*big.Int{big.NewInt(0), big.NewInt(1), p, new(big.Int).Add(p, big.NewInt(1)), new(big.Int).Sub(p, big.NewInt(1)), q, new(big.Int).Add(q, big.NewInt(1)), new(big.Int).Sub(pow2(255), big.NewInt(1))}
	mask := new(big.Int).Sub(pow2(37), big.NewInt(1))
	for _, a := range vs {
		for _, b := range vs {
			w := &distinctCircuit{}
			for i := 0; i < 7; i++ {
				w.A[i] = new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(a), uint(37*i)), mask)
				w.B[i] = new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(b), uint(37*i)), mask)
			}
			wit, e := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if e != nil {
				t.Fatal(e)
			}
			_, e = cs.Solve(wit)
			want := new(big.Int).Mod(a, p).Cmp(new(big.Int).Mod(b, p)) != 0
			if (e == nil) != want {
				t.Fatalf("a=%s b=%s err=%v", a, b, e)
			}
		}
	}
}
