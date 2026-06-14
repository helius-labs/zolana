package transaction

import (
	gadgetlib "light/light-prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

const (
	p256LimbBits    = 128
	p256MessageBits = 248
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

func p256MessageHashToP256Fr(api frontend.API, messageHash frontend.Variable) (*emulated.Element[emulated.P256Fr], error) {
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, err
	}
	return fr.FromBits(api.ToBinary(messageHash, p256MessageBits)...), nil
}
