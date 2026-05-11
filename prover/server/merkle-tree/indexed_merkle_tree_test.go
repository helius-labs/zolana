package merkle_tree

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIndexedMerkleTreeInit(t *testing.T) {
	expectedRoot := []byte{12, 192, 184, 61, 225, 169, 250, 219, 72, 31, 85, 251, 98, 186, 97, 83, 160, 211, 181, 216, 86, 130, 15, 129, 178, 199, 135, 240, 163, 58, 240, 219}

	tree, err := NewIndexedMerkleTree(26)
	require.NoError(t, err)

	err = tree.Init()
	require.NoError(t, err)

	root := tree.Tree.Root.Bytes()
	require.Equal(t, expectedRoot, root)

	require.Equal(t, uint32(0), tree.IndexArray.Get(0).Index)
	require.Equal(t, "0", tree.IndexArray.Get(0).Value.String())

	maxVal := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))
	require.Equal(t, maxVal, tree.IndexArray.Get(0).NextValue)
	require.Len(t, tree.IndexArray.Elements, 1)
	require.Equal(t, uint32(1), tree.IndexArray.CurrentNodeIndex)
}

func TestIndexedMerkleTreeAppend(t *testing.T) {
	tree, err := NewIndexedMerkleTree(26)
	require.NoError(t, err)

	err = tree.Init()
	require.NoError(t, err)

	value := big.NewInt(30)
	err = tree.Append(value)
	require.NoError(t, err)

	expectedRootFirstAppend := []byte{18, 210, 177, 207, 132, 232, 166, 171, 149, 166, 95, 175, 189, 87, 214, 204, 41, 132, 24, 175, 122, 252, 120, 118, 68, 169, 16, 250, 149, 139, 14, 121}

	root := tree.Tree.Root.Bytes()

	require.Equal(t, expectedRootFirstAppend, root)

	require.Equal(t, uint32(0), tree.IndexArray.Get(0).Index)
	require.Equal(t, "0", tree.IndexArray.Get(0).Value.String())

	maxVal := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))

	require.Equal(t, uint32(1), tree.IndexArray.Get(1).Index)
	require.Equal(t, "30", tree.IndexArray.Get(1).Value.String())
	require.Equal(t, maxVal, tree.IndexArray.Get(1).NextValue)

	value = big.NewInt(42)
	err = tree.Append(value)
	require.NoError(t, err)

	expectedRootSecondAppend := []byte{45, 242, 215, 173, 43, 96, 199, 85, 120, 124, 89, 79, 128, 69, 141, 118, 120, 67, 192, 16, 42, 75, 34, 18, 174, 59, 55, 58, 229, 72, 190, 14}

	root = tree.Tree.Root.Bytes()

	require.Equal(t, expectedRootSecondAppend, root)

	value = big.NewInt(12)
	err = tree.Append(value)
	require.NoError(t, err)

	expectedRootThirdAttempt := []byte{24, 4, 103, 62, 36, 147, 104, 245, 147, 222, 116, 243, 153, 89, 210, 69, 117, 248, 103, 35, 162, 136, 234, 244, 113, 152, 175, 75, 113, 137, 112, 62}

	root = tree.Tree.Root.Bytes()
	require.Equal(t, expectedRootThirdAttempt, root)
}
