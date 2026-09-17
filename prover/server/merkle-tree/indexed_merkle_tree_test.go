package merkle_tree

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Root of a tree whose only leaf is `leaf` at index 0.
func singleLeafRoot(leaf *big.Int, height int) *big.Int {
	root := leaf
	for i := 0; i < height; i++ {
		root = TreeHash(root, new(big.Int).SetBytes(ZERO_BYTES[i][:]))
	}
	return root
}

func TestIndexedMerkleTreeInit(t *testing.T) {
	tree, err := NewIndexedMerkleTree(26)
	require.NoError(t, err)
	require.NoError(t, tree.Init())

	maxVal := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))
	root := tree.Tree.Root.Value()
	require.Equal(t, singleLeafRoot(TreeHash(big.NewInt(0), maxVal), 26), &root)

	require.Equal(t, uint32(0), tree.IndexArray.Get(0).Index)
	require.Equal(t, "0", tree.IndexArray.Get(0).Value.String())
	require.Equal(t, maxVal, tree.IndexArray.Get(0).NextValue)
	require.Len(t, tree.IndexArray.Elements, 1)
	require.Equal(t, uint32(1), tree.IndexArray.CurrentNodeIndex)
}

func TestIndexedMerkleTreeAppend(t *testing.T) {
	tree, err := NewIndexedMerkleTree(26)
	require.NoError(t, err)
	require.NoError(t, tree.Init())
	maxVal := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))

	for _, value := range []int64{30, 42, 12} {
		require.NoError(t, tree.Append(big.NewInt(value)))
		for i := range tree.IndexArray.Elements {
			element := tree.IndexArray.Get(uint32(i))
			proof, err := tree.GetProof(i)
			require.NoError(t, err)
			ok, err := tree.Verify(i, element, proof)
			require.NoError(t, err)
			require.True(t, ok, "element %d after appending %d", i, value)
		}
	}

	// 0 -> 12 -> 30 -> 42 -> max, in insertion order 0, 30, 42, 12.
	require.Equal(t, "12", tree.IndexArray.Get(0).NextValue.String())
	require.Equal(t, "42", tree.IndexArray.Get(1).NextValue.String())
	require.Equal(t, maxVal, tree.IndexArray.Get(2).NextValue)
	require.Equal(t, "30", tree.IndexArray.Get(3).NextValue.String())

	// A wrong element does not verify.
	proof, err := tree.GetProof(1)
	require.NoError(t, err)
	wrong := *tree.IndexArray.Get(1)
	wrong.NextValue = big.NewInt(43)
	ok, err := tree.Verify(1, &wrong, proof)
	require.NoError(t, err)
	require.False(t, ok)
}
