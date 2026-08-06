package gadget_test

import (
	"math/big"
	"testing"

	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// openCircuit stands in for a fold that opens one inner public input and
// constrains what is inside it.
type openCircuit struct {
	Public   emulated.Element[sw_bn254.ScalarField]
	Preimage [2]frontend.Variable
	// The opened value, asserted so a wrong opening cannot pass unnoticed.
	Opened frontend.Variable
}

func (c *openCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	opened, err := gadget.OpenPublicInput(api, field, &c.Public, c.Preimage[:])
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Opened, opened)
	return nil
}

func assignment(public, a, b, opened *big.Int) *openCircuit {
	return &openCircuit{
		Public:   emulated.ValueOf[sw_bn254.ScalarField](public),
		Preimage: [2]frontend.Variable{a, b},
		Opened:   opened,
	}
}

func chain(assert *test.Assert, a, b *big.Int) *big.Int {
	h, err := poseidon.Hash([]*big.Int{a, b})
	assert.NoError(err)
	return h
}

func TestOpenPublicInputAcceptsTheCommittedPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	a, b := big.NewInt(3), big.NewInt(5)
	h := chain(assert, a, b)

	assert.NoError(test.IsSolved(
		&openCircuit{},
		assignment(h, a, b, h),
		ecc.BN254.ScalarField(),
	))
}

func TestOpenPublicInputRejectsAWrongPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	a, b := big.NewInt(3), big.NewInt(5)
	h := chain(assert, a, b)

	assert.Error(test.IsSolved(
		&openCircuit{},
		assignment(h, a, big.NewInt(6), h),
		ecc.BN254.ScalarField(),
	))
}

func TestOpenPublicInputRejectsAReorderedPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	a, b := big.NewInt(3), big.NewInt(5)
	h := chain(assert, a, b)

	assert.Error(test.IsSolved(
		&openCircuit{},
		assignment(h, b, a, h),
		ecc.BN254.ScalarField(),
	))
}

func TestOpenPublicInputReturnsTheEmulatedValue(t *testing.T) {
	assert := test.NewAssert(t)
	a, b := big.NewInt(3), big.NewInt(5)
	h := chain(assert, a, b)

	assert.Error(test.IsSolved(
		&openCircuit{},
		assignment(h, a, b, new(big.Int).Add(h, big.NewInt(1))),
		ecc.BN254.ScalarField(),
	))
}
