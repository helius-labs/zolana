package transaction

import (
	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

const (
	p256LimbBits    = 128
	p256ScalarBits  = 256
	p256MessageBits = 248
)

func NullifierPkCircuit(api frontend.API, nullifierSecret frontend.Variable) frontend.Variable {
	return poseidon.HashCircuit(api, []frontend.Variable{nullifierSecret})
}

func OwnerHashCircuit(
	api frontend.API,
	ownerKeyHash frontend.Variable,
	nullifierPk frontend.Variable,
) frontend.Variable {
	return poseidon.HashCircuit(api, []frontend.Variable{ownerKeyHash, nullifierPk})
}

func P256PkFieldCircuit(
	api frontend.API,
	yIsOdd frontend.Variable,
	xLow128 frontend.Variable,
	xHigh128 frontend.Variable,
) frontend.Variable {
	xHash := poseidon.HashCircuit(api, []frontend.Variable{xLow128, xHigh128})
	return poseidon.HashCircuit(api, []frontend.Variable{yIsOdd, xHash})
}

func P256PkFieldFromPubkeyCircuit(
	api frontend.API,
	pub gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr],
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
	x := fp.ReduceStrict(&point.X)
	y := fp.ReduceStrict(&point.Y)
	yBits := fp.ToBits(y)
	xBits := fp.ToBits(x)
	xLow128 := gnarkbits.FromBinary(api, xBits[:p256LimbBits])
	xHigh128 := gnarkbits.FromBinary(api, xBits[p256LimbBits:p256ScalarBits])
	return P256PkFieldCircuit(api, yBits[0], xLow128, xHigh128), nil
}

func p256MessageHashToP256Fr(api frontend.API, messageHash frontend.Variable) (*emulated.Element[emulated.P256Fr], error) {
	bits := api.ToBinary(messageHash, p256MessageBits)
	padded := make([]frontend.Variable, p256ScalarBits)
	copy(padded, bits)
	for i := p256MessageBits; i < p256ScalarBits; i++ {
		padded[i] = frontend.Variable(0)
	}
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, err
	}
	return fr.FromBits(padded...), nil
}
