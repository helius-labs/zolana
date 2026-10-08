package emcurve

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
)

type keyAgreementCircuit struct {
	NoLookups bool `gnark:"-"`
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
	Ephemeral [65]frontend.Variable `gnark:",public"`
	Shared    [32]frontend.Variable `gnark:",public"`
}

func (c *keyAgreementCircuit) Define(api frontend.API) error {
	eph := ScalarMulGeneratorFor(api, c.Scalar, !c.NoLookups)
	assertBytesEqual(api, eph[:], c.Ephemeral[:])
	got := ECDHFor(api, c.Scalar, c.PublicKey, !c.NoLookups)
	assertBytesEqual(api, got[:], c.Shared[:])
	return nil
}

type consumerCircuit struct {
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
	Packed    [6]frontend.Variable `gnark:",public"`
}

func packLoHi(api frontend.API, bytes []frontend.Variable) (frontend.Variable, frontend.Variable) {
	lo := frontend.Variable(0)
	for i := 0; i < 31; i++ {
		lo = api.Add(lo, api.Mul(bytes[i], new(big.Int).Lsh(big.NewInt(1), uint(8*(30-i)))))
	}
	if len(bytes) == 33 {
		return lo, api.Add(api.Mul(bytes[31], 256), bytes[32])
	}
	return lo, bytes[31]
}

func (c *consumerCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.PublicKey[0], 4)
	for i := 1; i < 65; i++ {
		api.ToBinary(c.PublicKey[i], 8)
	}
	PointOnCurve(api, c.PublicKey)
	recipient := CompressPubkey(api, c.PublicKey)
	ephemeral := CompressPubkey(api, ScalarMulGenerator(api, c.Scalar))
	shared := ECDH(api, c.Scalar, c.PublicKey)
	var out [6]frontend.Variable
	out[0], out[1] = packLoHi(api, recipient[:])
	out[2], out[3] = packLoHi(api, ephemeral[:])
	out[4], out[5] = packLoHi(api, shared[:])
	for i := range out {
		api.AssertIsEqual(out[i], c.Packed[i])
	}
	return nil
}

func TestConstraintCounts(t *testing.T) {
	for _, row := range []struct {
		name    string
		circuit frontend.Circuit
	}{
		{"ecdh", &ecdhCircuit{}},
		{"generator", &generatorCircuit{}},
		{"ecdh and generator", &keyAgreementCircuit{}},
		{"byte entry points", &consumerCircuit{}},
		{"AgreeKey", &agreeKeyCircuit{}},
	} {
		cs := compile(t, row.circuit)
		t.Logf("%-20s constraints %7d internal variables %7d", row.name, cs.GetNbConstraints(), cs.GetNbInternalVariables())
	}
}

func CompressPubkey(api frontend.API, uncompressed [65]frontend.Variable) [33]frontend.Variable {
	bits := api.ToBinary(uncompressed[64], 8)
	parity := bits[0]

	var compressed [33]frontend.Variable
	compressed[0] = api.Add(2, parity)
	for i := 0; i < 32; i++ {
		compressed[1+i] = uncompressed[1+i]
	}
	return compressed
}
