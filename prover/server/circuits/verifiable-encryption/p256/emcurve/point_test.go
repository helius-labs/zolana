// Tested invariants and diagnostics:
//
//  1. Coordinate bytes are canonical and reject a noncanonical encoding.
//  2. Canonical limb checks accept values below the modulus and reject values at or
//     above it.
//  3. Forged output-byte splits are rejected.
//  4. ECDH reduces scalars, accepts the six exceptional residues, and rejects infinity.
//  5. ECDH rejects incorrect prefixes, nonbyte coordinates, and noncanonical coordinates.
//  6. Exceptional scalar multiplication matches both host coordinates and rejects altered y.
package emcurve

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// Invariant 1: Coordinate bytes are canonical and reject a noncanonical encoding.
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

// Invariant 2: Canonical limb checks accept values below the modulus and reject values at or above it.
func TestLimbsBelowModulus(t *testing.T) {
	cs := compile(t, &belowModulusCircuit{Limbs: make([]frontend.Variable, emfield.LookupLayout.NbLimbs)})
	p := emulated.P256Fp{}.Modulus()
	for _, row := range []struct {
		value  *big.Int
		accept bool
	}{
		{big.NewInt(0), true},
		{new(big.Int).Sub(p, big.NewInt(1)), true},
		{p, false},
		{new(big.Int).Sub(pow2(256), big.NewInt(1)), false},
	} {
		witness, err := frontend.NewWitness(&belowModulusCircuit{Limbs: fieldLimbValues(row.value)}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("value %x: accept=%v err=%v", row.value, row.accept, err)
		}
	}
}

// Invariant 3: Forged output-byte splits are rejected.
func TestOutputBytesRejectForgedSplit(t *testing.T) {
	cs := compile(t, &generatorCircuit{})
	witness, _ := frontend.NewWitness(generatorWitnessFor(t, mergeScalar), ecc.BN254.ScalarField())
	forged := solver.OverrideHint(solver.GetHintID(p256LimbBytesHint), func(q *big.Int, in, out []*big.Int) error {
		if err := p256LimbBytesHint(q, in, out); err != nil {
			return err
		}
		last := len(out) - 1
		if out[last-1].Sign() > 0 {
			out[last-1].Sub(out[last-1], big.NewInt(1))
			out[last].Add(out[last], big.NewInt(256))
		}
		return nil
	})
	err := cs.IsSolved(witness, forged)
	if err == nil || !strings.Contains(err.Error(), "is not satisfied") {
		t.Fatalf("forged byte split: %v", err)
	}
}

// Invariant 4: ECDH reduces scalars, accepts the six exceptional residues, and rejects infinity.
func TestECDHRefusesInfinityAndReducesScalars(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdhCircuit{NoLookups: noLookups})
		peer := peerKey(t).PublicKey()
		for _, row := range scalarRows(t) {
			t.Run(row.name, func(t *testing.T) {
				row.check(t, cs, row.ecdhWitness(t, peer))
			})
		}
	})
}

// Invariant 5: ECDH rejects incorrect prefixes, nonbyte coordinates, and noncanonical coordinates.
func TestECDHRejectsMalformedEncoding(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdhCircuit{NoLookups: noLookups})
		row := scalarRow{scalar: mergeScalar, reduced: mergeScalar}
		peer := peerKey(t).PublicKey()
		honest := row.ecdhWitness(t, peer)
		assertCircuitResult(t, cs, honest, true)
		t.Run("wrong prefix", func(t *testing.T) {
			w := *honest
			w.PublicKey[0] = 5
			bad := append([]byte{}, peer.Bytes()...)
			bad[0] = 5
			if _, err := ecdh.P256().NewPublicKey(bad); err == nil {
				t.Fatal("host accepted malformed key")
			}
			assertCircuitResult(t, cs, &w, false)
		})
		t.Run("non byte coordinate", func(t *testing.T) {
			w := *honest
			w.PublicKey[1] = int(peer.Bytes()[1]) - 1
			w.PublicKey[2] = int(peer.Bytes()[2]) + 256
			assertCircuitResult(t, cs, &w, false)
		})
		t.Run("noncanonical x", func(t *testing.T) {
			x, y := smallCurvePoint(t)
			key, err := ecdh.P256().NewPublicKey(elliptic.Marshal(elliptic.P256(), x, y))
			if err != nil {
				t.Fatal(err)
			}
			w := row.ecdhWitness(t, key)
			alias := new(big.Int).Add(x, elliptic.P256().Params().P)
			setBytes(w.PublicKey[1:33], alias.FillBytes(make([]byte, 32)))
			assertCircuitResult(t, cs, w, false)
		})
	})
}

// Invariant 6: Exceptional scalar multiplication matches both host coordinates and rejects altered y.
func TestScalarMulExceptionalCoordinates(t *testing.T) {
	peer := peerKey(t).PublicKey().Bytes()
	px, py := elliptic.Unmarshal(elliptic.P256(), peer)
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &scalarMulCoordinatesCircuit{NoLookups: noLookups})
		for _, row := range scalarRows(t) {
			if row.reduced == nil {
				continue
			}
			t.Run(row.name, func(t *testing.T) {
				w := &scalarMulCoordinatesCircuit{}
				setBytes(w.Scalar[:], row.scalar.FillBytes(make([]byte, 32)))
				setBytes(w.PublicKey[:], peer)
				x, y := elliptic.P256().ScalarMult(px, py, row.reduced.Bytes())
				setBytes(w.Result[:], elliptic.Marshal(elliptic.P256(), x, y))
				assertCircuitResult(t, cs, w, true)
				// ECDH's X alone cannot distinguish a sign error; assert full Y,
				// then make that coordinate incorrect and require rejection.
				w.Result[64] = int(y.FillBytes(make([]byte, 32))[31]) ^ 1
				assertCircuitResult(t, cs, w, false)
			})
		}
	})
}

// Test circuits and shared helpers.

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
	name    string
	scalar  *big.Int
	reduced *big.Int
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
		{name: "one", scalar: big.NewInt(1), reduced: big.NewInt(1)},
		{name: "minus one", scalar: new(big.Int).Sub(n, big.NewInt(1)), reduced: new(big.Int).Sub(n, big.NewInt(1))},
		{name: "three", scalar: big.NewInt(3), reduced: big.NewInt(3)},
		{name: "minus inverse of three", scalar: new(big.Int).Sub(n, inverseOfThree), reduced: new(big.Int).Sub(n, inverseOfThree)},
		{name: "minus three", scalar: minusThree, reduced: minusThree},
		{name: "inverse of three", scalar: inverseOfThree, reduced: inverseOfThree},
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

func (r scalarRow) check(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit) {
	t.Helper()

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

type belowModulusCircuit struct {
	Limbs []frontend.Variable
}

func (c *belowModulusCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	cv.canonicalLimbs(cv.fp.FromLimbs(c.Limbs))
	return nil
}

type scalarMulCoordinatesCircuit struct {
	NoLookups         bool `gnark:"-"`
	Scalar            [32]frontend.Variable
	PublicKey, Result [65]frontend.Variable
}

func (c *scalarMulCoordinatesCircuit) Define(api frontend.API) error {
	result := ScalarMulFor(api, c.Scalar, c.PublicKey, !c.NoLookups)
	assertBytesEqual(api, result[:], c.Result[:])
	return nil
}

func assertCircuitResult(t *testing.T, cs constraint.ConstraintSystem, w frontend.Circuit, accept bool) {
	t.Helper()
	wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	err = cs.IsSolved(wit)
	if (err == nil) != accept {
		t.Fatalf("accept=%v: %v", accept, err)
	}
	if err != nil && !strings.Contains(err.Error(), "is not satisfied") {
		t.Fatalf("not a constraint rejection: %v", err)
	}
}
