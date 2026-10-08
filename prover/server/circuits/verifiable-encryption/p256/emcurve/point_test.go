package emcurve

import (
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

type fpBytesCircuit struct {
	Limbs []frontend.Variable
	Bytes [32]frontend.Variable `gnark:",public"`
}

func (c *fpBytesCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	got := cv.toBytes(cv.fp.FromLimbs(c.Limbs))
	for i := range got {
		api.AssertIsEqual(got[i], c.Bytes[i])
	}
	return nil
}

func fpBytesWitness(value *big.Int, bytes *big.Int) *fpBytesCircuit {
	w := fpBytesCircuit{Limbs: fieldLimbValues(value)}
	raw := bytes.FillBytes(make([]byte, 32))
	for i := range w.Bytes {
		w.Bytes[i] = raw[i]
	}
	return &w
}

func TestFpBytesAreCanonical(t *testing.T) {
	assert := test.NewAssert(t)
	p := emulated.P256Fp{}.Modulus()
	x := big.NewInt(0x1234_5678)
	shifted := new(big.Int).Add(x, p)
	if shifted.BitLen() > 256 {
		t.Fatalf("x + p must fit 256 bits for the test to mean anything")
	}
	circuit := &fpBytesCircuit{Limbs: make([]frontend.Variable, emfield.LookupLayout.NbLimbs)}
	assert.ProverSucceeded(circuit, fpBytesWitness(x, x), test.WithCurves(ecc.BN254))
	assert.ProverFailed(circuit, fpBytesWitness(shifted, x), test.WithCurves(ecc.BN254))
	assert.ProverFailed(circuit, fpBytesWitness(shifted, shifted), test.WithCurves(ecc.BN254))
}

type generatorCircuit struct {
	NoLookups bool `gnark:"-"`
	Scalar    [32]frontend.Variable
	Point     [65]frontend.Variable `gnark:",public"`
}

func (c *generatorCircuit) Define(api frontend.API) error {
	got := ScalarMulGeneratorFor(api, c.Scalar, !c.NoLookups)
	assertBytesEqual(api, got[:], c.Point[:])
	return nil
}

type ecdhCircuit struct {
	NoLookups bool `gnark:"-"`
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
	Shared    [32]frontend.Variable `gnark:",public"`
}

func (c *ecdhCircuit) Define(api frontend.API) error {
	got := ECDHFor(api, c.Scalar, c.PublicKey, !c.NoLookups)
	assertBytesEqual(api, got[:], c.Shared[:])
	return nil
}

func assertBytesEqual(api frontend.API, got, want []frontend.Variable) {
	for i := range got {
		api.AssertIsEqual(got[i], want[i])
	}
}

type scalarRow struct {
	name        string
	scalar      *big.Int
	reduced     *big.Int
	exceptional bool
}

func scalarRows(t *testing.T) []scalarRow {
	t.Helper()
	n := GroupOrder()
	s := big.NewInt(0x1234_5678)
	shifted := new(big.Int).Add(s, n)
	if shifted.BitLen() > 256 {
		t.Fatal("s + n must fit 256 bits")
	}
	inverseOfThree := new(big.Int).ModInverse(big.NewInt(3), n)
	minusThree := new(big.Int).Sub(n, big.NewInt(3))
	return []scalarRow{
		{name: "zero", scalar: big.NewInt(0)},
		{name: "group order", scalar: n},
		{name: "one", scalar: big.NewInt(1), reduced: big.NewInt(1), exceptional: true},
		{name: "minus three", scalar: minusThree, reduced: minusThree, exceptional: true},
		{name: "inverse of three", scalar: inverseOfThree, reduced: inverseOfThree, exceptional: true},
		{name: "two", scalar: big.NewInt(2), reduced: big.NewInt(2)},
		{name: "scalar plus group order", scalar: shifted, reduced: s},
	}
}

func (r scalarRow) privateKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.P256().NewPrivateKey(r.reduced.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	return key
}

func (r scalarRow) generatorWitness(t *testing.T) *generatorCircuit {
	t.Helper()
	var w generatorCircuit
	setBytes(w.Scalar[:], r.scalar.FillBytes(make([]byte, 32)))
	point := infinityPoint()
	if r.reduced != nil {
		point = r.privateKey(t).PublicKey().Bytes()
	}
	setBytes(w.Point[:], point)
	return &w
}

func (r scalarRow) ecdhWitness(t *testing.T, peer *ecdh.PublicKey) *ecdhCircuit {
	t.Helper()
	var w ecdhCircuit
	setBytes(w.Scalar[:], r.scalar.FillBytes(make([]byte, 32)))
	setBytes(w.PublicKey[:], peer.Bytes())
	shared := make([]byte, 32)
	if r.reduced != nil {
		var err error
		if shared, err = r.privateKey(t).ECDH(peer); err != nil {
			t.Fatalf("ecdh: %v", err)
		}
	}
	setBytes(w.Shared[:], shared)
	return &w
}

func infinityPoint() []byte {
	point := make([]byte, 65)
	point[0] = 0x04
	return point
}

func setBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = int(b)
	}
}

func compile(t *testing.T, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cs
}

func (r scalarRow) check(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit, rejectsExceptional bool) {
	t.Helper()
	if rejectsExceptional && r.exceptional {
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatalf("new witness: %v", err)
		}
		if cs.IsSolved(witness) == nil {
			t.Fatal("expected the exceptional scalar to be rejected")
		}
		return
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	err = cs.IsSolved(witness)
	switch {
	case r.reduced == nil && err == nil:
		t.Fatal("expected the scalar of infinity to be rejected")
	case r.reduced != nil && err != nil:
		t.Fatalf("solve: %v", err)
	}
}

func TestGeneratorRefusesInfinityAndReducesScalars(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &generatorCircuit{NoLookups: noLookups})
		for _, row := range scalarRows(t) {
			t.Run(row.name, func(t *testing.T) {
				row.check(t, cs, row.generatorWitness(t), false)
			})
		}
	})
}

func TestECDHRefusesInfinityAndReducesScalars(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdhCircuit{NoLookups: noLookups})
		peer := peerKey(t).PublicKey()
		for _, row := range scalarRows(t) {
			t.Run(row.name, func(t *testing.T) {
				row.check(t, cs, row.ecdhWitness(t, peer), true)
			})
		}
	})
}

func peerKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x33 ^ byte(i)
	}
	key, err := ecdh.P256().NewPrivateKey(seed)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	return key
}
