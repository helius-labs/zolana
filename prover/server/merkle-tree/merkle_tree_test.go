package merkle_tree

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func readVectors(t *testing.T) treeHashVectors {
	raw, err := os.ReadFile("../../../test-vectors/tree_hash.json")
	require.NoError(t, err)
	var v treeHashVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

func fromHex(t *testing.T, s string) *big.Int {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return new(big.Int).SetBytes(b)
}

func TestTreeHashVectors(t *testing.T) {
	v := readVectors(t)
	require.Equal(t, TreeHashWidth, v.Parameters.Width)
	require.Equal(t, TreeHashFullRounds, v.Parameters.FullRounds)
	require.Equal(t, TreeHashPartialRounds, v.Parameters.PartialRounds)
	for _, c := range v.Compress {
		require.Equal(t, fromHex(t, c.Hash), TreeHash(fromHex(t, c.Left), fromHex(t, c.Right)))
	}
	require.Len(t, v.ZeroNodes, len(ZERO_BYTES))
	for i, z := range v.ZeroNodes {
		require.Equal(t, z, hex.EncodeToString(ZERO_BYTES[i][:]), "zero node %d", i)
	}
	for i := 1; i < len(ZERO_BYTES); i++ {
		require.Equal(t, ZERO_BYTES[i], TreeHashBytes(ZERO_BYTES[i-1], ZERO_BYTES[i-1]))
	}
}

func TestSubtrees(t *testing.T) {
	depth := 4
	tree := NewTree(depth)
	subtrees := tree.GetRightmostSubtrees(depth)
	for i := range subtrees {
		require.Equal(t, new(big.Int).SetBytes(ZERO_BYTES[i][:]), subtrees[i])
	}

	// Two leaves of 1 fill the leftmost height-1 subtree.
	one := big.NewInt(1)
	tree.Update(0, *one)
	tree.Update(1, *one)
	subtrees = tree.GetRightmostSubtrees(depth)
	node1 := TreeHash(one, one)
	require.Equal(t, one, subtrees[0])
	require.Equal(t, node1, subtrees[1])
	require.Equal(t, TreeHash(node1, new(big.Int).SetBytes(ZERO_BYTES[1][:])), subtrees[2])

	// Two leaves of 2 complete the leftmost height-2 subtree.
	two := big.NewInt(2)
	tree.Update(2, *two)
	tree.Update(3, *two)
	subtrees = tree.GetRightmostSubtrees(depth)
	node2 := TreeHash(node1, TreeHash(two, two))
	require.Equal(t, two, subtrees[0])
	require.Equal(t, node1, subtrees[1])
	require.Equal(t, node2, subtrees[2])
	require.Equal(t, TreeHash(node2, new(big.Int).SetBytes(ZERO_BYTES[2][:])), subtrees[3])
}
