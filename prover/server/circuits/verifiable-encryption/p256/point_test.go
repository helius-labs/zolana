package p256

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type fpBytesCircuit struct {
	Limbs [4]frontend.Variable
	Bytes [32]frontend.Variable `gnark:",public"`
}

func (c *fpBytesCircuit) Define(api frontend.API) error {
	elem := emulated.Element[emulated.P256Fp]{Limbs: c.Limbs[:]}
	got := emulatedFpToBytes(api, &elem)
	for i := range got {
		api.AssertIsEqual(got[i], c.Bytes[i])
	}
	return nil
}

func fpBytesWitness(value *big.Int, bytes *big.Int) *fpBytesCircuit {
	var w fpBytesCircuit
	mask := new(big.Int).SetUint64(^uint64(0))
	for i := range w.Limbs {
		limb := new(big.Int).Rsh(value, uint(64*i))
		w.Limbs[i] = limb.And(limb, mask)
	}
	raw := bytes.FillBytes(make([]byte, 32))
	for i := range w.Bytes {
		w.Bytes[i] = raw[i]
	}
	return &w
}

// x + p fits 256 bits for small x, the bytes must still spell x.
func TestFpBytesAreCanonical(t *testing.T) {
	assert := test.NewAssert(t)
	p := emulated.P256Fp{}.Modulus()
	x := big.NewInt(0x1234_5678)
	shifted := new(big.Int).Add(x, p)
	if shifted.BitLen() > 256 {
		t.Fatalf("x + p must fit 256 bits for the test to mean anything")
	}
	assert.ProverSucceeded(&fpBytesCircuit{}, fpBytesWitness(x, x), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(&fpBytesCircuit{}, fpBytesWitness(shifted, x), test.WithCurves(ecc.BN254))
	assert.ProverFailed(&fpBytesCircuit{}, fpBytesWitness(shifted, shifted), test.WithCurves(ecc.BN254))
}
