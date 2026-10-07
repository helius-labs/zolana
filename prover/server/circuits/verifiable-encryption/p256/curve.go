package p256

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

func newP256Curve(api frontend.API) *sw_emulated.Curve[emulated.P256Fp, emulated.P256Fr] {
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](api, sw_emulated.GetP256Params())
	if err != nil {
		panic(err)
	}
	return curve
}

func newAgreementField(api frontend.API) *agreementField {
	fp, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		panic(err)
	}
	return fp
}

func newScalarField(api frontend.API) *emulated.Field[emulated.P256Fr] {
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		panic(err)
	}
	return fr
}
