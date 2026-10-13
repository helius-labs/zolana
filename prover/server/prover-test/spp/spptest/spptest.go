// Package spptest holds test-only helpers shared across the SPP packages so the
// individual *_test.go files do not each re-roll the same wrappers. It depends
// only on protocol/poseidon/parse-level types, never on the circuit packages,
// which keeps it importable from their internal tests without an import cycle.
package spptest

import (
	"crypto/ed25519"
	"math/big"
	mrand "math/rand"
	"testing"

	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark/frontend"
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

// MustUtxoHash hashes utxo under the raw id of the tree that holds it.
func MustUtxoHash(t testing.TB, utxo protocol.Utxo, treeID *big.Int) *big.Int {
	t.Helper()
	value, err := protocol.UtxoHash(utxo, treeID)
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

func MustHashChain4(t testing.TB, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := protocol.HashChain4(inputs)
	return MustHash(t, value, err)
}

func MustRightHashChain4(t testing.TB, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := protocol.RightHashChain4(inputs)
	return MustHash(t, value, err)
}

func MustNonZeroHashChain(t testing.TB, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := protocol.NonZeroHashChain(inputs)
	return MustHash(t, value, err)
}

func MustPrivateTxHash(t testing.TB, inputs, outputs, addresses []*big.Int, blinding *big.Int) *big.Int {
	t.Helper()
	value, err := protocol.PrivateTxHash(inputs, outputs, addresses, blinding)
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

// FixedEd25519Key derives a deterministic Ed25519 key from a fixed seed value.
func FixedEd25519Key(t testing.TB, seed int64) ed25519.PrivateKey {
	t.Helper()
	var seedBytes [ed25519.SeedSize]byte
	big.NewInt(seed).FillBytes(seedBytes[:])
	return ed25519.NewKeyFromSeed(seedBytes[:])
}

// Ed25519PublicKeyBytes returns the 32-byte compressed public key of priv.
func Ed25519PublicKeyBytes(priv ed25519.PrivateKey) [32]byte {
	var pk [32]byte
	copy(pk[:], priv.Public().(ed25519.PublicKey))
	return pk
}

// Ed25519OwnerPkHash is the Solana-tagged owner identity of priv's public key.
func Ed25519OwnerPkHash(t testing.TB, priv ed25519.PrivateKey) *big.Int {
	t.Helper()
	identity, err := protocol.SolanaPkField(Ed25519PublicKeyBytes(priv))
	return MustHash(t, identity, err)
}
