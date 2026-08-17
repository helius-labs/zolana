package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

// EdDSA-Poseidon over the BN254-embedded twisted Edwards curve (Baby JubJub),
// matching gnark's std/signature/eddsa verification equation
//
//	[cofactor]([S]B - [hRAM]A - R) == identity,  hRAM = Poseidon(R.X, R.Y, A.X, A.Y, msg)
//
// gnark-crypto's own eddsa package cannot be used here: GenerateKey clamps the
// secret scalar above 2^254, which does not fit a single circuit variable, and
// its Sign hashes serialized bytes instead of field elements.

// SpendSecretBits bounds the secret scalar. The circuit range-checks the secret
// to this width because the subgroup order is 251 bits while the scalar field
// is 254: without the bound, secret, secret+order, ... secret+7*order are
// distinct field elements sharing one public key, and each would derive a
// different nullifier for the same UTXO.
const SpendSecretBits = 250

// spendNonceDomain separates the nonce derivation from every other Poseidon use
// in the protocol.
const spendNonceDomain = 0x5350454e44 // "SPEND"

// SpendPoint is a curve point in affine coordinates. Both coordinates are
// native field elements, which is why this rail is cheap in-circuit.
type SpendPoint struct {
	X *big.Int
	Y *big.Int
}

// SpendKey authorizes spending the UTXOs whose owner hash commits to Public.
type SpendKey struct {
	Secret *big.Int
	Public SpendPoint
}

// SpendSignature is an EdDSA-Poseidon signature.
type SpendSignature struct {
	R SpendPoint
	S *big.Int
}

// IdentitySpendPoint is the neutral element, the convention for slots that do
// not sign: dummy padding and address slots. It is on the curve and in the
// prime-order subgroup, so the circuit can run its curve checks ungated.
func IdentitySpendPoint() SpendPoint {
	return SpendPoint{X: big.NewInt(0), Y: big.NewInt(1)}
}

// IdentitySpendSignature is the signature a non-signing slot carries. It
// satisfies the verification equation under the identity key, which is exactly
// why the circuit must reject the identity key for real UTXOs.
func IdentitySpendSignature() SpendSignature {
	return SpendSignature{R: IdentitySpendPoint(), S: big.NewInt(0)}
}

// SpendKeyOrder is the prime order of the base point's subgroup.
func SpendKeyOrder() *big.Int {
	params := twistededwards.GetEdwardsCurve()
	return new(big.Int).Set(&params.Order)
}

// NewSpendKey derives the public key of a secret scalar.
func NewSpendKey(secret *big.Int) (SpendKey, error) {
	if secret == nil || secret.Sign() < 0 {
		return SpendKey{}, fmt.Errorf("spp: spend secret must be non-negative")
	}
	if secret.BitLen() > SpendSecretBits {
		return SpendKey{}, fmt.Errorf(
			"spp: spend secret must be below 2^%d, got %d bits",
			SpendSecretBits,
			secret.BitLen(),
		)
	}
	public := scalarBaseMul(secret)
	return SpendKey{Secret: new(big.Int).Set(secret), Public: public}, nil
}

// SignSpend signs msg for one input slot. The nonce is derived from the secret,
// the message and the slot index: deterministic so a benchmark witness is
// reproducible, slot-dependent so two slots of one key never share an R, and
// message-dependent because reusing a nonce across messages leaks the secret.
func SignSpend(key SpendKey, msg *big.Int, slot int) (SpendSignature, error) {
	if key.Secret == nil || msg == nil {
		return SpendSignature{}, fmt.Errorf("spp: spend signature needs a secret and a message")
	}
	order := SpendKeyOrder()
	nonce, err := poseidon.Hash([]*big.Int{
		big.NewInt(spendNonceDomain),
		key.Secret,
		msg,
		big.NewInt(int64(slot)),
	})
	if err != nil {
		return SpendSignature{}, fmt.Errorf("spp: spend nonce: %w", err)
	}
	nonce.Mod(nonce, order)

	r := scalarBaseMul(nonce)
	hram, err := SpendChallenge(r, key.Public, msg)
	if err != nil {
		return SpendSignature{}, err
	}
	s := new(big.Int).Mul(hram, key.Secret)
	s.Add(s, nonce)
	s.Mod(s, order)

	signature := SpendSignature{R: r, S: s}
	// A host-side bug here would otherwise surface as an unsatisfiable witness
	// with no diagnostic, deep inside a proving run.
	if err := VerifySpend(key.Public, msg, signature); err != nil {
		return SpendSignature{}, fmt.Errorf("spp: freshly produced spend signature does not verify: %w", err)
	}
	return signature, nil
}

// SpendChallenge is hRAM, the value both the host and the circuit hash. The
// circuit consumes the raw Poseidon output as a scalar, so it is not reduced
// modulo the subgroup order here.
func SpendChallenge(r SpendPoint, public SpendPoint, msg *big.Int) (*big.Int, error) {
	hram, err := poseidon.Hash([]*big.Int{r.X, r.Y, public.X, public.Y, msg})
	if err != nil {
		return nil, fmt.Errorf("spp: spend challenge: %w", err)
	}
	return hram, nil
}

// VerifySpend mirrors the in-circuit equation exactly, including the cofactor
// multiplication and the final identity comparison.
func VerifySpend(public SpendPoint, msg *big.Int, signature SpendSignature) error {
	params := twistededwards.GetEdwardsCurve()
	if signature.S == nil || signature.S.Sign() < 0 || signature.S.Cmp(&params.Order) >= 0 {
		return fmt.Errorf("spp: spend signature S out of range")
	}
	hram, err := SpendChallenge(signature.R, public, msg)
	if err != nil {
		return err
	}

	publicPoint, err := toPointAffine(public)
	if err != nil {
		return fmt.Errorf("spp: spend public key: %w", err)
	}
	rPoint, err := toPointAffine(signature.R)
	if err != nil {
		return fmt.Errorf("spp: spend signature R: %w", err)
	}

	// [S]B - [hRAM]A - R
	var lhs, scaled, sum twistededwards.PointAffine
	lhs.ScalarMultiplication(&params.Base, signature.S)
	scaled.ScalarMultiplication(publicPoint, hram)
	scaled.Neg(&scaled)
	sum.Add(&lhs, &scaled)
	rPoint.Neg(rPoint)
	sum.Add(&sum, rPoint)

	cofactor := new(big.Int).SetUint64(8)
	if !params.Cofactor.IsUint64() || params.Cofactor.Uint64() != 8 {
		return fmt.Errorf("spp: unexpected curve cofactor %s", params.Cofactor.String())
	}
	sum.ScalarMultiplication(&sum, cofactor)

	if !sum.IsZero() {
		return fmt.Errorf("spp: spend signature does not verify")
	}
	return nil
}

func scalarBaseMul(scalar *big.Int) SpendPoint {
	params := twistededwards.GetEdwardsCurve()
	var point twistededwards.PointAffine
	point.ScalarMultiplication(&params.Base, scalar)
	return fromPointAffine(&point)
}

func toPointAffine(point SpendPoint) (*twistededwards.PointAffine, error) {
	if point.X == nil || point.Y == nil {
		return nil, fmt.Errorf("missing coordinate")
	}
	var out twistededwards.PointAffine
	out.X.SetBigInt(point.X)
	out.Y.SetBigInt(point.Y)
	if !out.IsOnCurve() {
		return nil, fmt.Errorf("point is not on the curve")
	}
	return &out, nil
}

func fromPointAffine(point *twistededwards.PointAffine) SpendPoint {
	x := new(big.Int)
	y := new(big.Int)
	point.X.BigInt(x)
	point.Y.BigInt(y)
	return SpendPoint{X: x, Y: y}
}
