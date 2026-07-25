package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// Signers is a transaction's single source of truth for who signed it: one entry
// per input slot, built once per proof by the rail's signer builder, and masked
// to 0 for slots that carry no content. Every later check that needs a signature
// resolves against it instead of re-deriving the rail's rule. Rails build it at
// the granularity their checks can resolve: the signer pk hash (what the input
// ownership binding needs, and what the default zone's public output owner tags
// carry) or the owner hash a signer proved (SignerOwners, for the custom zone
// where output owners stay private).
type Signers []frontend.Variable

// Contains returns 1 iff identity is non-zero and equals one of the signers. The
// non-zero requirement keeps masked slots from ever matching.
func (s Signers) Contains(api frontend.API, identity frontend.Variable) frontend.Variable {
	prod := frontend.Variable(1)
	for _, signer := range s {
		prod = api.Mul(prod, api.Sub(identity, signer))
	}
	return api.Mul(api.IsZero(prod), api.Sub(1, api.IsZero(identity)))
}

// ContainsEach returns one bit per identity, set when that identity signed. The
// variants use it to hand Transaction.Constrain the per-output-slot bit a
// data-carrying output requires.
func (s Signers) ContainsEach(api frontend.API, identities []frontend.Variable) []frontend.Variable {
	signed := make([]frontend.Variable, len(identities))
	for i, identity := range identities {
		signed[i] = s.Contains(api, identity)
	}
	return signed
}

// EddsaOnlySigners builds the signer array for the Solana-only rails: the
// program verified one ed25519 signature per input slot and published its pk
// hash as that slot's owner tag. P256-owned entries route on the 0 sentinel and
// these rails carry no P256 witness, so a slot that carries content must name a
// non-zero ed25519 signer.
func EddsaOnlySigners(api frontend.API, inputs []Input, ownerPkHashes []frontend.Variable) Signers {
	signers := make(Signers, len(inputs))
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		pkHash := ownerPkHashes[i]
		assertWhen(api, carriesContent, api.Sub(1, api.IsZero(pkHash)))
		signers[i] = api.Mul(carriesContent, pkHash)
	}
	return signers
}

// P256Signer is the one witnessed P256 key that signs for every P256-owned slot
// of a proof, with the validity bit of its single signature over the P256
// message.
type P256Signer struct {
	PkField  frontend.Variable
	SigValid frontend.Variable
	// Sentinel is the owner tag value that routes a slot to this key. The default
	// zone uses the public P256SigningPkField, so P256 input owners are public;
	// the custom zone variants route anonymously on the 0 sentinel.
	Sentinel frontend.Variable
}

// NewP256Signer verifies the shared signature over the P256 message digest
// carried as two big-endian 128-bit limbs, and derives the key's pk_field.
func NewP256Signer(
	api frontend.API,
	pub P256PublicKey,
	sig P256Signature,
	msgLow, msgHigh, sentinel frontend.Variable,
) (P256Signer, error) {
	pkField, err := OwnerPkFieldFromPubkeyCircuit(api, pub)
	if err != nil {
		return P256Signer{}, err
	}
	message, err := p256MessageHashToP256Fr(api, msgLow, msgHigh)
	if err != nil {
		return P256Signer{}, err
	}
	return P256Signer{
		PkField: pkField,
		SigValid: pub.IsValid(
			api,
			sw_emulated.GetCurveParams[emulated.P256Fp](),
			message,
			&sig,
		),
		Sentinel: sentinel,
	}, nil
}

// P256Signers builds the signer array for the P256 rails: a slot whose owner tag
// equals the rail's sentinel is signed by the one witnessed P256 key, which
// needs its shared signature over the P256 message to be valid; every other slot
// is signed by the ed25519 signer the program published.
func P256Signers(api frontend.API, inputs []Input, ownerPkHashes []frontend.Variable, p256 P256Signer) Signers {
	signers := make(Signers, len(inputs))
	for i, in := range inputs {
		carriesContent := in.isUtxoOrAddress(api)
		pkHash := ownerPkHashes[i]
		isP256 := api.IsZero(api.Sub(pkHash, p256.Sentinel))
		assertWhen(api, api.Mul(carriesContent, isP256), p256.SigValid)
		signers[i] = api.Mul(carriesContent, api.Select(isP256, p256.PkField, pkHash))
	}
	return signers
}
