package base

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
)

// canonicalKeyCircuit bounds the key bytes as ECDH does before agreeCanonical checks them.
type canonicalKeyCircuit struct{ Key [32]frontend.Variable }

func (c *canonicalKeyCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	for _, b := range c.Key {
		rc.Check(b, 8)
	}
	assertBelowP(api, c.Key)
	return nil
}

func TestCanonicalX25519RefusesEncodingsAtOrAboveP(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &canonicalKeyCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	encode := func(n *big.Int) *canonicalKeyCircuit {
		var b [32]byte
		n.FillBytes(b[:])
		w := new(canonicalKeyCircuit)
		for i := range b {
			w.Key[i] = b[31-i]
		}
		return w
	}
	check := func(n *big.Int, valid bool) {
		t.Helper()
		witness, err := frontend.NewWitness(encode(n), q)
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(witness, hintattack.SkipMissingLookupQueries(t))
		if valid {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			hintattack.RequireConstraintRejection(t, err)
		}
	}
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for _, n := range []*big.Int{big.NewInt(0), big.NewInt(255), new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(p, big.NewInt(256))} {
		check(n, true)
	}
	for _, n := range []*big.Int{p, new(big.Int).Add(p, big.NewInt(18)), new(big.Int).Lsh(big.NewInt(1), 255)} {
		check(n, false)
	}
}
