package ed25519

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/ed25519/internal/sha512"
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// Inputs are standard Ed25519 encodings: PublicKey is compressed Edwards y,
// Signature is R || S (S little endian), and Message has compile-time length.
// Public/private visibility is chosen by the enclosing circuit.
type Inputs struct {
	PublicKey [32]frontend.Variable
	Signature [64]frontend.Variable
	Message   []frontend.Variable
}

// Verify asserts Agave precompile/ed25519-dalek 1.0.1 verify_strict acceptance. It rejects
// S >= L, malformed points, small-order A and R. Mixed
// torsion points and noncanonical point encodings are handled as dalek does;
// both the prime and torsion equations are checked.
// It returns the exact public-key encoding hashed into the challenge.
func Verify(api frontend.API, in Inputs) [32]frontend.Variable {
	transcript := make([]frontend.Variable, 0, 64+len(in.Message))
	transcript = append(transcript, in.Signature[:32]...)
	transcript = append(transcript, in.PublicKey[:]...)
	transcript = append(transcript, in.Message...)
	digest := sha512.Hash(api, transcript)
	return verifyDigest(api, in.PublicKey, in.Signature, digest)
}

// verifyDigest is kept private: callers use Verify to bind R, key and message
// to the challenge. Tests use this boundary to measure the arithmetic alone.
func verifyDigest(api frontend.API, publicKey [32]frontend.Variable, signature [64]frontend.Variable, digest [64]frontend.Variable) [32]frontend.Variable {
	c := newCurve(api)
	var rEncoded [32]frontend.Variable
	copy(rEncoded[:], signature[:32])
	a := c.decodeEncoding(publicKey)
	r := c.decodeEncoding(rEncoded)
	s := c.byteElement(c.fr, signature[32:], 253)
	c.fr.AssertCanonical(s)
	h := c.fr.Eval(emfield.T(1, c.byteElement(c.fr, digest[:], 512)))
	c.fr.AssertCanonical(h)
	hbits := c.lowBits(h.Limbs()[0], 3)
	a0, ta := c.splitTorsion(a)
	r0, tr := c.splitTorsion(r)
	c.assertTorsion(ta, tr, hbits)
	c.shortVerify(a0, r0, h, s)
	return publicKey
}

// oneHot constructs each bit monomial once, then applies inclusion-exclusion.
// Callers constrain all bits to be Boolean. Reusing those products across
// columns follows the multilinear-selection idea in circomlib's mux2/mux3.
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
