// Package spptest holds test-only helpers shared across the SPP packages so the
// individual *_test.go files do not each re-roll the same wrappers. It depends
// only on protocol/poseidon/parse-level types, never on the circuit packages,
// which keeps it importable from their internal tests without an import cycle.
package spptest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	mrand "math/rand"
	"testing"

	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/internal/p256key"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// Fe returns value as a field element.
func Fe(value int64) *big.Int {
	return big.NewInt(value)
}

// MustHash fails the test if err is non-nil, otherwise returns value.
func MustHash(t testing.TB, value *big.Int, err error) *big.Int {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected hash error: %v", err)
	}
	return value
}

func MustPoseidon(t testing.TB, width int, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := poseidon.HashWithT(width, inputs)
	return MustHash(t, value, err)
}

func MustUtxoHash(t testing.TB, utxo protocol.Utxo) *big.Int {
	t.Helper()
	value, err := protocol.UtxoHash(utxo)
	return MustHash(t, value, err)
}

func MustNullifierPk(t testing.TB, secret *big.Int) *big.Int {
	t.Helper()
	value, err := protocol.NullifierPk(secret)
	return MustHash(t, value, err)
}

func MustOwnerHash(t testing.TB, ownerKeyHash, nullifierPk *big.Int) *big.Int {
	t.Helper()
	value, err := protocol.OwnerHash(ownerKeyHash, nullifierPk)
	return MustHash(t, value, err)
}

func MustNullifier(t testing.TB, utxoHash, blinding, secret *big.Int) *big.Int {
	t.Helper()
	value, err := protocol.Nullifier(utxoHash, blinding, secret)
	return MustHash(t, value, err)
}

func MustHashChain(t testing.TB, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := protocol.HashChain(inputs)
	return MustHash(t, value, err)
}

func MustPrivateTxHash(t testing.TB, inputs, outputs, addresses []*big.Int, externalDataHash *big.Int) *big.Int {
	t.Helper()
	value, err := protocol.PrivateTxHash(inputs, outputs, addresses, externalDataHash)
	return MustHash(t, value, err)
}

// MustP256MessageDigest returns the full SHA-256 ECDSA message digest of
// privateTxHash (the bytes the P256 owner signs).
func MustP256MessageDigest(t testing.TB, privateTxHash *big.Int) [32]byte {
	t.Helper()
	digest, err := protocol.P256MessageDigest(privateTxHash)
	if err != nil {
		t.Fatalf("p256 message digest: %v", err)
	}
	return digest
}

// MustP256MessageLimbs returns the big-endian low/high 128-bit limbs of the
// message digest, as assigned to the circuit witness.
func MustP256MessageLimbs(t testing.TB, privateTxHash *big.Int) (low, high *big.Int) {
	t.Helper()
	digest := MustP256MessageDigest(t, privateTxHash)
	low, high = protocol.P256MessageLimbs(digest)
	return low, high
}

// MustP256MessageHashField returns the public-input field Poseidon(low, high)
// for the message digest of privateTxHash.
func MustP256MessageHashField(t testing.TB, privateTxHash *big.Int) *big.Int {
	t.Helper()
	low, high := MustP256MessageLimbs(t, privateTxHash)
	return MustP256FieldFromLimbs(t, low, high)
}

// MustP256FieldFromLimbs folds explicit message-hash limbs into the public-input
// field Poseidon(low, high). On the Solana-only rail both limbs are 0.
func MustP256FieldFromLimbs(t testing.TB, low, high *big.Int) *big.Int {
	t.Helper()
	value, err := protocol.P256MessageHashField(low, high)
	return MustHash(t, value, err)
}

func MustBuildSparseStateTree(t testing.TB, entries map[uint64]*big.Int) (*big.Int, map[uint64]protocol.StateTreeWitness) {
	t.Helper()
	root, proofs, err := protocol.BuildSparseStateTree(entries)
	if err != nil {
		t.Fatalf("build sparse state tree: %v", err)
	}
	return root, proofs
}

func MustNewNullifierTree(t testing.TB) *protocol.NullifierTree {
	t.Helper()
	tree, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatalf("new nullifier tree: %v", err)
	}
	return tree
}

func MustFieldBytes(t testing.TB, value *big.Int) [32]byte {
	t.Helper()
	out, err := parse.FieldBytes(value)
	if err != nil {
		t.Fatalf("field bytes: %v", err)
	}
	return out
}

func MustNonInclusion(t testing.TB, tree *protocol.NullifierTree, target *big.Int) protocol.NonInclusionWitness {
	t.Helper()
	witness, err := tree.NonInclusionWitness(target)
	if err != nil {
		t.Fatalf("non-inclusion witness: %v", err)
	}
	return witness
}

// AsBigInt extracts the concrete *big.Int backing a witness assignment value.
func AsBigInt(value frontend.Variable) *big.Int {
	switch v := value.(type) {
	case *big.Int:
		return v
	case int:
		return big.NewInt(int64(v))
	case int64:
		return big.NewInt(v)
	default:
		panic("spptest: unsupported frontend.Variable value type")
	}
}

func ToBigInts(values []frontend.Variable) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = AsBigInt(value)
	}
	return out
}

func ToVariables(values []*big.Int) []frontend.Variable {
	out := make([]frontend.Variable, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func ZeroVariables(n int) []frontend.Variable {
	out := make([]frontend.Variable, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}

func RepeatBigInt(value *big.Int, count int) []*big.Int {
	out := make([]*big.Int, count)
	for i := range out {
		out[i] = new(big.Int).Set(value)
	}
	return out
}

// RandomField returns a small pseudo-random field element drawn from rng.
func RandomField(rng *mrand.Rand) *big.Int {
	return new(big.Int).SetUint64(rng.Uint64() >> 16)
}

func RandomFields(rng *mrand.Rand, count int) []*big.Int {
	out := make([]*big.Int, count)
	for i := range out {
		out[i] = RandomField(rng)
	}
	return out
}

// FixedP256Key derives a deterministic P256 key from a fixed scalar.
func FixedP256Key(t testing.TB, scalar int64) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := p256key.PrivateKeyFromScalar(big.NewInt(scalar))
	if err != nil {
		t.Fatalf("fixed P256 key: %v", err)
	}
	return priv
}

func P256PubkeyAssignment(priv *ecdsa.PrivateKey) gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr] {
	return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.X),
		Y: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.Y),
	}
}

// UnusedP256Witness returns a valid-but-irrelevant P256 public key and signature
// over msg, for inputs that are not P256-owned and so do not constrain the key.
func UnusedP256Witness(msg []byte) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], gnarkecdsa.Signature[emulated.P256Fr], error) {
	priv, err := p256key.PrivateKeyFromScalar(big.NewInt(7))
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, err
	}
	return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.Y),
		}, gnarkecdsa.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		}, nil
}
