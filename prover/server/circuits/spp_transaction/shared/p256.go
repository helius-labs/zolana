package shared

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

const (
	p256LimbBits = 128
)

// P256PublicKey and P256Signature are the gnark ECDSA witness types pinned to
// the P256 instantiation used by the ownership rail.
type (
	P256PublicKey = gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	P256Signature = gnarkecdsa.Signature[emulated.P256Fr]
)

// p256PkFieldGadget folds a P256 public key (parity bit and the two 128-bit
// halves of the x-coordinate) into a single field element.
type p256PkFieldGadget struct {
	YIsOdd   frontend.Variable
	XLow128  frontend.Variable
	XHigh128 frontend.Variable
}

func (gadget p256PkFieldGadget) DefineGadget(api frontend.API) interface{} {
	xHash := gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.XLow128, gadget.XHigh128})
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.YIsOdd, xHash})
}

// P256PkFieldFromPointCircuit folds an already-parsed P256 point into pk_field.
// It does not assert the point is on the curve; callers that need that guarantee
// (e.g. after p256.PointOnCurve) ensure it separately.
func P256PkFieldFromPointCircuit(
	api frontend.API,
	point sw_emulated.AffinePoint[emulated.P256Fp],
) (frontend.Variable, error) {
	fp, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		return nil, err
	}
	xLow128, xHigh128 := p256XLimbs(api, fp, point)
	return abstractor.Call(api, p256PkFieldGadget{
		YIsOdd:   fp.ToBitsCanonical(&point.Y)[0],
		XLow128:  xLow128,
		XHigh128: xHigh128,
	}), nil
}

// p256XLimbs splits a point's x-coordinate into its two canonical big-endian
// 128-bit halves, the form both pk_field encodings hash.
func p256XLimbs(
	api frontend.API,
	fp *emulated.Field[emulated.P256Fp],
	point sw_emulated.AffinePoint[emulated.P256Fp],
) (frontend.Variable, frontend.Variable) {
	xBits := fp.ToBitsCanonical(&point.X)
	return gnarkbits.FromBinary(api, xBits[:p256LimbBits]),
		gnarkbits.FromBinary(api, xBits[p256LimbBits:])
}

// ownerPkFieldGadget folds a P256 OWNER public key into pk_field using only the
// x-coordinate: Poseidon(x_low128, x_high128). The y-parity is intentionally
// excluded (it is carried in the encrypted data, not the owner identity), so a
// P256 owner pk_field has the same shape as an ed25519 owner pk_field
// (hash_field over the two 128-bit halves). The VIEWING key keeps the
// parity-folding p256PkFieldGadget.
type ownerPkFieldGadget struct {
	XLow128  frontend.Variable
	XHigh128 frontend.Variable
}

func (gadget ownerPkFieldGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.XLow128, gadget.XHigh128})
}

// ownerPkFieldFromPubkeyCircuit derives the parity-free owner pk_field from a
// P256 public key (asserting it is on the curve).
func ownerPkFieldFromPubkeyCircuit(
	api frontend.API,
	pub P256PublicKey,
) (frontend.Variable, error) {
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](
		api,
		sw_emulated.GetCurveParams[emulated.P256Fp](),
	)
	if err != nil {
		return nil, err
	}
	point := sw_emulated.AffinePoint[emulated.P256Fp](pub)
	curve.AssertIsOnCurve(&point)
	fp, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		return nil, err
	}
	xLow128, xHigh128 := p256XLimbs(api, fp, point)
	return abstractor.Call(api, ownerPkFieldGadget{
		XLow128:  xLow128,
		XHigh128: xHigh128,
	}), nil
}

// p256MessageHashToP256Fr reconstructs the full 256-bit SHA-256 ECDSA message
// digest from its two big-endian 128-bit limbs. Each limb is range-checked to
// 128 bits by ToBinary; concatenating low (bits 0..128) then high (bits
// 128..256) yields the canonical 256-bit scalar fed to the emulated P256 curve.
func p256MessageHashToP256Fr(api frontend.API, low, high frontend.Variable) (*emulated.Element[emulated.P256Fr], error) {
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, err
	}
	bits := append(api.ToBinary(low, p256LimbBits), api.ToBinary(high, p256LimbBits)...)
	return fr.FromBits(bits...), nil
}
