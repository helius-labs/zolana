package spp

import (
	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

type UtxoCircuitFields struct {
	Domain          frontend.Variable
	Owner           frontend.Variable
	AssetID         frontend.Variable
	AssetAmount     frontend.Variable
	Blinding        frontend.Variable
	DataHash        frontend.Variable
	PolicyData      frontend.Variable
	PolicyProgramID frontend.Variable
}

func UtxoHashCircuit(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 9, []frontend.Variable{
		u.Domain,
		u.Owner,
		u.AssetID,
		u.AssetAmount,
		u.Blinding,
		u.DataHash,
		u.PolicyData,
		u.PolicyProgramID,
	})
}

func NullifierPkCircuit(api frontend.API, nullifierSecret frontend.Variable) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 2, []frontend.Variable{nullifierSecret})
}

func OwnerHashCircuit(
	api frontend.API,
	ownerKeyHash frontend.Variable,
	nullifierPk frontend.Variable,
) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 3, []frontend.Variable{ownerKeyHash, nullifierPk})
}

func P256OwnerKeyHashCircuit(
	api frontend.API,
	yIsOdd frontend.Variable,
	xLow frontend.Variable,
	xHigh frontend.Variable,
) frontend.Variable {
	xHash := poseidon.HashCircuitWithT(api, 3, []frontend.Variable{xLow, xHigh})
	return poseidon.HashCircuitWithT(api, 3, []frontend.Variable{yIsOdd, xHash})
}

func P256OwnerKeyHashFromPubkeyCircuit(
	api frontend.API,
	pub gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr],
) frontend.Variable {
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](
		api,
		sw_emulated.GetCurveParams[emulated.P256Fp](),
	)
	if err != nil {
		panic(err)
	}
	point := sw_emulated.AffinePoint[emulated.P256Fp](pub)
	curve.AssertIsOnCurve(&point)

	fp, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		panic(err)
	}
	x := fp.ReduceStrict(&point.X)
	y := fp.ReduceStrict(&point.Y)
	yBits := fp.ToBits(y)
	xBits := fp.ToBits(x)
	xHigh := gnarkbits.FromBinary(api, xBits[:128])
	xLow := gnarkbits.FromBinary(api, xBits[128:256])
	return P256OwnerKeyHashCircuit(api, yBits[0], xLow, xHigh)
}

func privateTxHashToP256Fr(api frontend.API, privateTxHash frontend.Variable) *emulated.Element[emulated.P256Fr] {
	bits := api.ToBinary(privateTxHash, 254)
	padded := make([]frontend.Variable, 256)
	copy(padded, bits)
	for i := 254; i < 256; i++ {
		padded[i] = frontend.Variable(0)
	}
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		panic(err)
	}
	return fr.FromBits(padded...)
}

func NullifierHashCircuit(
	api frontend.API,
	utxoHash frontend.Variable,
	blinding frontend.Variable,
	nullifierSecret frontend.Variable,
) frontend.Variable {
	return poseidon.HashCircuitWithT(api, 4, []frontend.Variable{
		utxoHash,
		blinding,
		nullifierSecret,
	})
}

func HashChainCircuit(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}

	h := inputs[len(inputs)-1]
	for i := len(inputs) - 2; i >= 0; i-- {
		h = poseidon.HashCircuitWithT(api, 3, []frontend.Variable{inputs[i], h})
	}
	return h
}

func PrivateTxHashCircuit(
	api frontend.API,
	inputUtxoHashes []frontend.Variable,
	outputUtxoHashes []frontend.Variable,
	externalDataHash frontend.Variable,
	expiryUnixTs frontend.Variable,
) frontend.Variable {
	inputChain := HashChainCircuit(api, inputUtxoHashes)
	outputChain := HashChainCircuit(api, outputUtxoHashes)
	return poseidon.HashCircuitWithT(api, 5, []frontend.Variable{
		inputChain,
		outputChain,
		externalDataHash,
		expiryUnixTs,
	})
}
