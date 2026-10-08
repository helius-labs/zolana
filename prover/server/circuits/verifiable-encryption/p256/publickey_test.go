// Tested invariants (shared with publickey_external_test.go):
//
//  1. Public-key derivation reduces scalars modulo the group order and rejects zero
//     residues.
//  2. Self-agreement matches host ECDH, including edge scalars, and rejects an altered
//     shared x-coordinate.
//  3. Self-agreement reduces scalars modulo the group order and rejects zero residues at
//     the order boundaries.
//  4. Self-agreement scalar inputs are constrained to bytes, including under forged
//     range-check hints.
//  5. Self-agreement rejects forged scalar-multiplication reports and mutated hints.
package p256

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/prover-test/hintattack"
)

// Invariant 1: Public-key derivation reduces scalars modulo the group order and rejects zero residues.
func TestPublicKeyRefusesInfinityAndReducesScalars(t *testing.T) {
	cs := compile(t, &publicKeyCircuit{})
	for _, row := range scalarRows(t) {
		t.Run(row.name, func(t *testing.T) {
			row.check(t, cs, row.publicKeyWitness(t))
		})
	}
}

// Invariant 2: Self-agreement matches host ECDH, including edge scalars, and rejects an altered shared x-coordinate.
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

// Invariant 3: Self-agreement reduces scalars modulo the group order and rejects zero residues at the order boundaries.
func TestSelfAgreeKeyRefusesInfinityAndReducesScalars(t *testing.T) {
	cs := compile(t, &selfAgreementCircuit{})
	for _, row := range scalarRows(t) {
		t.Run(row.name, func(t *testing.T) {
			row.check(t, cs, row.selfAgreementWitness(t))
		})
	}
}

// Invariant 5: Self-agreement rejects forged scalar-multiplication reports and mutated hints.
func TestSelfAgreeKeyRejectsReportForgery(t *testing.T) {
	n := elliptic.P256().Params().N
	cs := compile(t, &selfAgreementCircuit{})
	for _, row := range []struct {
		name     string
		scalar   *big.Int
		x        *big.Int
		mirrored bool
	}{
		{"off-curve result at scalar minus one", new(big.Int).Sub(n, big.NewInt(1)), new(big.Int).SetBytes([]byte("an x nobody can recompute later!")), false},
		{"zero x at scalar minus one", new(big.Int).Sub(n, big.NewInt(1)), big.NewInt(0), false},
		{"off-curve result at scalar one", big.NewInt(1), new(big.Int).SetBytes([]byte("an x nobody can recompute later!")), true},
		{"zero x at scalar one", big.NewInt(1), big.NewInt(0), true},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := scalarRow{scalar: row.scalar, reduced: row.scalar}.selfAgreementWitness(t)
			setBytes(w.SharedX[:], be32(row.x))
			if err := solveAgreement(t, cs, w); err == nil {
				t.Fatal("honest prover produced the forged shared secret")
			}
			err := solveAgreement(t, cs, w, forgedHints(t, row.x, row.mirrored)...)
			if err == nil {
				t.Fatal("forged shared secret accepted")
			}
			t.Logf("rejected: %v", err)
		})
	}
}

// Invariant 5: Self-agreement rejects forged scalar-multiplication reports and mutated hints.
func TestSelfAgreeKeyRejectsHintAttacks(t *testing.T) {
	cs := compile(t, &selfAgreementCircuit{})
	for _, row := range attackScalars() {
		w := scalarRow{name: row.name, scalar: row.scalar, reduced: row.scalar}.selfAgreementWitness(t)
		t.Run(row.name, func(t *testing.T) {
			hintattack.RunHintAttacks(t, cs, func(opts ...solver.Option) error {
				return solveAgreement(t, cs, w, opts...)
			})
		})
	}
}

// Test circuits and shared helpers.

type publicKeyCircuit struct {
	Scalar [32]frontend.Variable
	Packed [2]frontend.Variable `gnark:",public"`
}

func (c *publicKeyCircuit) Define(api frontend.API) error {
	lo, hi := DerivePublicKey(api, c.Scalar).Packed(api)
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
	got := SelfAgreeKey(api, DerivePublicKey(api, c.Scalar))
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
