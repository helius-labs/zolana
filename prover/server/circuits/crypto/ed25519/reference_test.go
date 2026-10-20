package ed25519

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/sha512"
)

// The pinned dalek corpus includes mixed-torsion acceptance. Keeping that
// predicate in tests prevents production callers from selecting it.
func verifyReference(api frontend.API, in Inputs) [32]frontend.Variable {
	transcript := append(append(append([]frontend.Variable{}, in.Signature[:32]...), in.PublicKey[:]...), in.Message...)
	return verifyDigestReference(api, in.PublicKey, in.Signature, sha512.Hash(api, transcript))
}

func verifyDigestReference(api frontend.API, publicKey [32]frontend.Variable, signature, digest [64]frontend.Variable) [32]frontend.Variable {
	v := decodeSignature(api, publicKey, signature, digest)
	c := v.curve
	a, ta := c.splitTorsion(v.a)
	r, tr := c.splitTorsion(v.r)
	c.assertTorsion(ta, tr, c.lowBits(v.h.Limbs()[0], 3))
	c.shortVerify(a, r, v.h, v.s)
	return publicKey
}

func (c *curve) assertTorsion(a, r frontend.Variable, hbits []frontend.Variable) {
	sum := c.api.Add(r, c.api.Mul(a, c.api.FromBinary(hbits[:3]...)))
	out, err := c.api.Compiler().NewHint(torsionQuotientHint, 1, sum)
	if err != nil {
		panic(err)
	}
	c.api.ToBinary(out[0], 3)
	c.api.AssertIsEqual(sum, c.api.Mul(out[0], 8))
}

func torsionQuotientHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) != 1 || len(out) != 1 {
		return errors.New("torsion quotient shape")
	}
	out[0].Rsh(in[0], 3)
	return nil
}
func init() { solver.RegisterHint(torsionQuotientHint) }
