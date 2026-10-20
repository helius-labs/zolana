package ed25519

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/sha512"
)

// Inputs are standard Ed25519 encodings: PublicKey is compressed Edwards y,
// Signature is R || S (S little endian), and Message has compile-time length.
// Public/private visibility is chosen by the enclosing circuit.
type Inputs struct {
	PublicKey [32]frontend.Variable
	Signature [64]frontend.Variable
	Message   []frontend.Variable
}

// Verify binds the exact message and key encodings to an Ed25519 signature.
// A and R must be canonically encoded nonidentity prime-subgroup points.
// S must be in [0,L). It returns the authenticated public-key bytes.
func Verify(api frontend.API, in Inputs) [32]frontend.Variable {
	// 1 - Binding the complete transcript prevents substituting a hinted challenge.
	transcript := make([]frontend.Variable, 0, 64+len(in.Message))
	transcript = append(transcript, in.Signature[:32]...)
	transcript = append(transcript, in.PublicKey[:]...)
	transcript = append(transcript, in.Message...)
	digest := sha512.Hash(api, transcript)
	return verifyDigest(api, in.PublicKey, in.Signature, digest)
}

// verifyDigest is private because only Verify binds this challenge to R, A and
// the message. Its input digest is the complete 64-byte SHA-512 output.
func verifyDigest(api frontend.API, publicKey [32]frontend.Variable, signature [64]frontend.Variable, digest [64]frontend.Variable) [32]frontend.Variable {
	// 2 - Canonical encodings give each accepted identity and scalar one representation.
	v := decodeSignature(api, publicKey, signature, digest)
	c := v.curve

	// 3 - The short equation is cancellable only on nonidentity prime-subgroup points.
	a0, ta := c.splitTorsion(v.a)
	r0, tr := c.splitTorsion(v.r)
	c.assertCanonicalPrime(v.a, ta)
	c.assertCanonicalPrime(v.r, tr)

	// 4 - The constrained nonzero short multiplier preserves the signature equation.
	c.shortVerify(a0, r0, v.h, v.s)
	return publicKey
}

type decodedSignature struct {
	curve *curve
	a, r  *point
	h, s  *nonnative.Element
}

// decodeSignature constrains byte encodings and scalar reduction. Its point
// candidates acquire curve/subgroup membership only through splitTorsion.
func decodeSignature(api frontend.API, publicKey [32]frontend.Variable, signature [64]frontend.Variable, digest [64]frontend.Variable) decodedSignature {
	c := newCurve(api)
	var rEncoded [32]frontend.Variable
	copy(rEncoded[:], signature[:32])
	a, r := c.decodeEncoding(publicKey), c.decodeEncoding(rEncoded)
	s := c.byteElement(c.fr, signature[32:], 253)
	c.fr.AssertCanonical(s)
	h := c.fr.Eval(nonnative.T(1, c.byteElement(c.fr, digest[:], 512)))
	c.fr.AssertCanonical(h)
	return decodedSignature{curve: c, a: a, r: r, h: h, s: s}
}

// splitTorsion proves the subgroup claim. Canonical x limbs make their
// nonzero sum an integer test. In the prime subgroup x=0 is only the identity.
func (c *curve) assertCanonicalPrime(p *point, torsion frontend.Variable) {
	c.fp.AssertCanonical(p.y)
	c.api.AssertIsEqual(torsion, 0)
	c.api.AssertIsDifferent(c.api.Add(0, 0, p.x.Limbs()...), 0)
}

// oneHot constructs each bit monomial once, then applies inclusion-exclusion.
// Callers constrain all bits to be Boolean. Reusing those products across
// columns follows the multilinear-selection idea in circomlib's mux2/mux3.
// Boyar, Find, Multiplicative Complexity of Vector Valued Boolean Functions, TCS 2018, §3.2, Prop. 4 and the proof of Thm. 7, https://arxiv.org/abs/1407.6169.
func oneHot(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	flags := make([]frontend.Variable, 1<<len(bits))
	flags[0] = 1
	for i, b := range bits {
		for mask := 0; mask < 1<<i; mask++ {
			flags[mask|1<<i] = api.Mul(flags[mask], b)
		}
	}
	for i := range bits {
		for mask := range flags {
			if mask&(1<<i) == 0 {
				flags[mask] = api.Sub(flags[mask], flags[mask|1<<i])
			}
		}
	}
	return flags
}
