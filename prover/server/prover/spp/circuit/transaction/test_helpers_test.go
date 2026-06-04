package transaction

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"light/light-prover/prover/poseidon"
	"light/light-prover/prover/spp/internal/p256key"
	"light/light-prover/prover/spp/model"
	"light/light-prover/prover/spp/parse"

	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

func fe(v int64) *big.Int {
	return big.NewInt(v)
}

func mustHash(t *testing.T, value *big.Int, err error) *big.Int {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected hash error: %v", err)
	}
	return value
}

func mustUtxoHash(t *testing.T, utxo model.Utxo) *big.Int {
	t.Helper()
	value, err := model.UtxoHash(utxo)
	return mustHash(t, value, err)
}

func mustPoseidon(t *testing.T, width int, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := poseidon.HashWithT(width, inputs)
	return mustHash(t, value, err)
}

func mustNullifierPk(t *testing.T, secret *big.Int) *big.Int {
	t.Helper()
	value, err := model.NullifierPk(secret)
	return mustHash(t, value, err)
}

func mustOwnerHash(t *testing.T, ownerKeyHash, nullifierPk *big.Int) *big.Int {
	t.Helper()
	value, err := model.OwnerHash(ownerKeyHash, nullifierPk)
	return mustHash(t, value, err)
}

func mustNullifierHash(t *testing.T, utxoHash, blinding, secret *big.Int) *big.Int {
	t.Helper()
	value, err := model.NullifierHash(utxoHash, blinding, secret)
	return mustHash(t, value, err)
}

func mustHashChain(t *testing.T, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := model.HashChain(inputs)
	return mustHash(t, value, err)
}

func mustPrivateTxHash(t *testing.T, inputs, outputs []*big.Int, externalDataHash, expiry *big.Int) *big.Int {
	t.Helper()
	value, err := model.PrivateTxHash(inputs, outputs, externalDataHash, expiry)
	return mustHash(t, value, err)
}

func mustBuildSparseStateTree(t *testing.T, entries map[uint64]*big.Int) (*big.Int, map[uint64]model.StateTreeWitness) {
	t.Helper()
	root, proofs, err := model.BuildSparseStateTree(entries)
	if err != nil {
		t.Fatalf("build sparse state tree: %v", err)
	}
	return root, proofs
}

func mustNewIndexedTree(t *testing.T) *model.IndexedTree {
	t.Helper()
	tree, err := model.NewIndexedTree()
	if err != nil {
		t.Fatalf("new indexed tree: %v", err)
	}
	return tree
}

func mustFieldBytes(t *testing.T, value *big.Int) [32]byte {
	t.Helper()
	out, err := parse.FieldBytes(value)
	if err != nil {
		t.Fatalf("field bytes: %v", err)
	}
	return out
}

func mustNonInclusion(t *testing.T, tree *model.IndexedTree, target *big.Int) model.NonInclusionWitness {
	t.Helper()
	witness, err := tree.NonInclusionChecked(target)
	if err != nil {
		t.Fatalf("non-inclusion witness: %v", err)
	}
	return witness
}

func inactiveP256Witness(msg []byte) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], gnarkecdsa.Signature[emulated.P256Fr], error) {
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
