package transaction

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

// P256PkFieldGadget folds a P256 public key (parity bit and the two 128-bit
// halves of the x-coordinate) into a single field element.
type P256PkFieldGadget struct {
	YIsOdd   frontend.Variable
	XLow128  frontend.Variable
	XHigh128 frontend.Variable
}

func (gadget P256PkFieldGadget) DefineGadget(api frontend.API) interface{} {
	xHash := gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.XLow128, gadget.XHigh128})
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.YIsOdd, xHash})
}

func P256PkFieldFromPubkeyCircuit(
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
	return P256PkFieldFromPointCircuit(api, point)
}

// P256PkFieldFromPointCircuit folds an already-parsed P256 point into pk_field.
// It does not assert the point is on the curve; callers that need that guarantee
// (e.g. P256PkFieldFromPubkeyCircuit, or after p256.PointOnCurve) ensure it
// separately.
func P256PkFieldFromPointCircuit(
	api frontend.API,
	point sw_emulated.AffinePoint[emulated.P256Fp],
) (frontend.Variable, error) {
	fp, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		return nil, err
	}
	yBits := fp.ToBitsCanonical(&point.Y)
	xBits := fp.ToBitsCanonical(&point.X)
	xLow128 := gnarkbits.FromBinary(api, xBits[:p256LimbBits])
	xHigh128 := gnarkbits.FromBinary(api, xBits[p256LimbBits:])
	return abstractor.Call(api, P256PkFieldGadget{
		YIsOdd:   yBits[0],
		XLow128:  xLow128,
		XHigh128: xHigh128,
	}), nil
}

// OwnerPkFieldGadget folds a P256 OWNER public key into pk_field using only the
// x-coordinate: Poseidon(x_low128, x_high128). The y-parity is intentionally
// excluded (it is carried in the encrypted data, not the owner identity), so a
// P256 owner pk_field has the same shape as an ed25519 owner pk_field
// (hash_field over the two 128-bit halves). The VIEWING key keeps the
// parity-folding P256PkFieldGadget.
type OwnerPkFieldGadget struct {
	XLow128  frontend.Variable
	XHigh128 frontend.Variable
}

func (gadget OwnerPkFieldGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.XLow128, gadget.XHigh128})
}

// OwnerPkFieldFromPubkeyCircuit derives the parity-free owner pk_field from a
// P256 public key (asserting it is on the curve).
func OwnerPkFieldFromPubkeyCircuit(
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
	xBits := fp.ToBitsCanonical(&point.X)
	xLow128 := gnarkbits.FromBinary(api, xBits[:p256LimbBits])
	xHigh128 := gnarkbits.FromBinary(api, xBits[p256LimbBits:])
	return abstractor.Call(api, OwnerPkFieldGadget{
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
