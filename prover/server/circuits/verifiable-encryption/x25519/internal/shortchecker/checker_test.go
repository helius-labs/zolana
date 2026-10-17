package shortchecker

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"testing"
)

type circuit struct {
	Scalar, Peer, Out [32]frontend.Variable
	Lay               emfield.Layout `gnark:"-"`
}

func (c *circuit) Define(api frontend.API) error {
	f := emfield.NewFor(api, prime(), c.Lay)
	var k, ub []frontend.Variable
	for i := range c.Scalar {
		k = append(k, api.ToBinary(c.Scalar[i], 8)...)
		ub = append(ub, api.ToBinary(c.Peer[i], 8)...)
	}
	ub = ub[:255]
	widths := f.ReducedWidths()
	limbs := make([]frontend.Variable, c.Lay.NbLimbs)
	for i, w := range widths {
		limbs[i] = api.FromBinary(ub[i*c.Lay.LimbBits : i*c.Lay.LimbBits+w]...)
	}
	shared := Multiply(api, f, f.Bounded(limbs, widths), k)
	f.AssertCanonical(shared)
	var bits []frontend.Variable
	for i, l := range shared.Limbs() {
		bits = append(bits, api.ToBinary(l, widths[i])...)
	}
	bits = append(bits, 0)
	for i := range c.Out {
		api.AssertIsEqual(api.FromBinary(bits[i*8:i*8+8]...), c.Out[i])
	}
	return nil
}
func TestCandidate(t *testing.T) {
	for _, lay := range []emfield.Layout{{NbLimbs: 6, LimbBits: 43, PieceBits: 11}, {NbLimbs: 8, LimbBits: 32, PieceBits: 11}} {
		t.Run(fmt.Sprint(lay), func(t *testing.T) {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit{Lay: lay})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("constraints %d", cs.GetNbConstraints())
			for j := 0; j < 4; j++ {
				sk := sha256.Sum256([]byte(fmt.Sprintf("short scalar %d", j)))
				pk := sha256.Sum256([]byte(fmt.Sprintf("short peer %d", j)))
				key, _ := ecdh.X25519().NewPrivateKey(sk[:])
				peer, _ := ecdh.X25519().NewPublicKey(pk[:])
				out, err := key.ECDH(peer)
				if err != nil {
					t.Fatal(err)
				}
				w := &circuit{Lay: lay}
				for i := range sk {
					w.Scalar[i] = sk[i]
					w.Peer[i] = pk[i]
					w.Out[i] = out[i]
				}
				wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = cs.Solve(wit); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// fromLimbs proves the test witness widths before attaching arithmetic bounds.
func fromLimbs(f *emfield.Field, limbs []frontend.Variable) *emfield.Element {
	widths := f.ReducedWidths()
	for i, limb := range limbs {
		f.RangeChecker().Check(limb, widths[i])
	}
	return f.Bounded(limbs, widths)
}
