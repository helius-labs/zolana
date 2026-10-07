package p256

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type fpBytesCircuit struct {
	Limbs [4]frontend.Variable
	Bytes [32]frontend.Variable `gnark:",public"`
}

func (c *fpBytesCircuit) Define(api frontend.API) error {
	elem := emulated.Element[emulated.P256Fp]{Limbs: c.Limbs[:]}
	got, _ := canonicalFpBytes(api, newAgreementField(api), &elem)
	assertBytesEqual(api, got[:], c.Bytes[:])
	return nil
}

func fpBytesWitness(value *big.Int, bytes *big.Int) *fpBytesCircuit {
	var w fpBytesCircuit
	mask := new(big.Int).SetUint64(^uint64(0))
	for i := range w.Limbs {
		limb := new(big.Int).Rsh(value, uint(64*i))
		w.Limbs[i] = limb.And(limb, mask)
	}
	setBytes(w.Bytes[:], bytes.FillBytes(make([]byte, 32)))
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
	assert.ProverSucceeded(&fpBytesCircuit{}, fpBytesWitness(x, x), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(&fpBytesCircuit{}, fpBytesWitness(shifted, x), test.WithCurves(ecc.BN254))
	assert.ProverFailed(&fpBytesCircuit{}, fpBytesWitness(shifted, shifted), test.WithCurves(ecc.BN254))
}

type publicKeyCircuit struct {
	Scalar [32]frontend.Variable
	Packed [2]frontend.Variable `gnark:",public"`
}

func (c *publicKeyCircuit) Define(api frontend.API) error {
	lo, hi := PublicKeyPacked(api, c.Scalar)
	api.AssertIsEqual(lo, c.Packed[0])
	api.AssertIsEqual(hi, c.Packed[1])
	return nil
}

type selfAgreementCircuit struct {
	Scalar    [32]frontend.Variable
	SharedX   [32]frontend.Variable `gnark:",public"`
	PublicKey [33]frontend.Variable `gnark:",public"`
}

func (c *selfAgreementCircuit) Define(api frontend.API) error {
	got := SelfAgreeKey(api, c.Scalar)
	assertBytesEqual(api, got.SharedX[:], c.SharedX[:])
	assertBytesEqual(api, got.PublicKey[:], c.PublicKey[:])
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
	n := elliptic.P256().Params().N
	s := big.NewInt(0x1234_5678)
	shifted := new(big.Int).Add(s, n)
	if shifted.BitLen() > 256 {
		t.Fatal("s + n must fit 256 bits")
	}
	return []scalarRow{
		{name: "zero", scalar: big.NewInt(0)},
		{name: "group order", scalar: n},
		{name: "one", scalar: big.NewInt(1), reduced: big.NewInt(1)},
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

func (r scalarRow) publicKeyWitness(t *testing.T) *publicKeyCircuit {
	t.Helper()
	var w publicKeyCircuit
	setBytes(w.Scalar[:], r.scalar.FillBytes(make([]byte, 32)))
	w.Packed[0], w.Packed[1] = 0, 0
	if r.reduced != nil {
		w.Packed[0], w.Packed[1] = packAgreementBytes(compressedKey(r.privateKey(t).PublicKey().Bytes()))
	}
	return &w
}

func (r scalarRow) agreementWitness(t *testing.T, peer *ecdh.PublicKey) *agreeKeyCircuit {
	t.Helper()
	if r.reduced != nil {
		return agreeKeyWitness(t, r.scalar, peer)
	}
	var w agreeKeyCircuit
	setBytes(w.Scalar[:], r.scalar.FillBytes(make([]byte, 32)))
	setBytes(w.PublicKey[:], peer.Bytes())
	for i := range w.Expected {
		w.Expected[i] = 0
	}
	return &w
}

func (r scalarRow) selfAgreementWitness(t *testing.T) *selfAgreementCircuit {
	t.Helper()
	var w selfAgreementCircuit
	setBytes(w.Scalar[:], r.scalar.FillBytes(make([]byte, 32)))
	shared := make([]byte, 32)
	public := make([]byte, 33)
	if r.reduced != nil {
		key := r.privateKey(t)
		var err error
		if shared, err = key.ECDH(key.PublicKey()); err != nil {
			t.Fatalf("ecdh: %v", err)
		}
		public = compressedKey(key.PublicKey().Bytes())
	}
	setBytes(w.SharedX[:], shared)
	setBytes(w.PublicKey[:], public)
	return &w
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

func TestPublicKeyRefusesInfinityAndReducesScalars(t *testing.T) {
	cs := compile(t, &publicKeyCircuit{})
	for _, row := range scalarRows(t) {
		t.Run(row.name, func(t *testing.T) {
			row.check(t, cs, row.publicKeyWitness(t))
		})
	}
}

func TestAgreeKeyRefusesInfinityAndReducesScalars(t *testing.T) {
	cs := compile(t, &agreeKeyCircuit{})
	peer := peerKey(t).PublicKey()
	for _, row := range scalarRows(t) {
		t.Run(row.name, func(t *testing.T) {
			row.check(t, cs, row.agreementWitness(t, peer))
		})
	}
}

func TestSelfAgreeKeyRefusesInfinityAndReducesScalars(t *testing.T) {
	cs := compile(t, &selfAgreementCircuit{})
	for _, row := range scalarRows(t) {
		t.Run(row.name, func(t *testing.T) {
			row.check(t, cs, row.selfAgreementWitness(t))
		})
	}
}

func TestSelfAgreeKeyMatchesHost(t *testing.T) {
	cs := compile(t, &selfAgreementCircuit{})
	seed := new(big.Int).SetBytes([]byte("a counters disclosure secret key"))
	row := scalarRow{name: "random", scalar: seed, reduced: new(big.Int).Mod(seed, elliptic.P256().Params().N)}
	row.check(t, cs, row.selfAgreementWitness(t))
	tampered := row.selfAgreementWitness(t)
	tampered.SharedX[31] = (int(tampered.SharedX[31].(int)) + 1) % 256
	witness, err := frontend.NewWitness(tampered, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if cs.IsSolved(witness) == nil {
		t.Fatal("tampered shared x accepted")
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
