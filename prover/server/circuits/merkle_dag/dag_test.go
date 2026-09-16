package merkledag

import (
	"math/big"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/test"
	"github.com/iden3/go-iden3-crypto/poseidon"

	"zolana/prover/circuits/gadget"
	"zolana/prover/prover-test/spp/protocol"
)

const depth = 32

type pair struct {
	Left, Right frontend.Variable
	Parent      frontend.Variable
}

type statement struct {
	Root, Digest frontend.Variable `gnark:",public"`
	Salt         frontend.Variable
	Leaves       []frontend.Variable
}

func (s *statement) bind(api frontend.API) {
	api.AssertIsEqual(s.Digest, gadget.HashChain4(api, append([]frontend.Variable{s.Salt}, s.Leaves...)))
}

type dagCircuit struct {
	statement
	Levels  [][]pair
	LeafRef []frontend.Variable
}

func newDAG(n, occupiedHeight int) *dagCircuit {
	c := &dagCircuit{statement: statement{Leaves: make([]frontend.Variable, n)}, Levels: make([][]pair, depth), LeafRef: make([]frontend.Variable, n)}
	for level := range c.Levels {
		width := min(n, 1<<max(0, occupiedHeight-level-1))
		c.Levels[level] = make([]pair, width)
	}
	return c
}

func (c *dagCircuit) Define(api frontend.API) error {
	c.bind(api)
	var upper logderivlookup.Table
	for level := depth - 1; level >= 0; level-- {
		current := logderivlookup.New(api)
		for _, node := range c.Levels[level] {
			hash := gadget.PoseidonHash(api, []frontend.Variable{node.Left, node.Right})
			if level == depth-1 {
				api.AssertIsEqual(hash, c.Root)
			} else {
				api.AssertIsEqual(hash, upper.Lookup(node.Parent)[0])
			}
			current.Insert(node.Left)
			current.Insert(node.Right)
		}
		upper = current
	}
	for i, leaf := range c.Leaves {
		api.AssertIsEqual(leaf, upper.Lookup(c.LeafRef[i])[0])
	}
	return nil
}

type pathCircuit struct {
	statement
	Indices    []frontend.Variable
	Paths      [][]frontend.Variable
	UpperIndex frontend.Variable
	UpperPath  []frontend.Variable
}

func newPaths(n int) *pathCircuit {
	c := &pathCircuit{statement: statement{Leaves: make([]frontend.Variable, n)}, Indices: make([]frontend.Variable, n), Paths: make([][]frontend.Variable, n)}
	for i := range c.Paths {
		c.Paths[i] = make([]frontend.Variable, depth)
	}
	return c
}

func (c *pathCircuit) Define(api frontend.API) error {
	c.bind(api)
	var common frontend.Variable
	for i, leaf := range c.Leaves {
		bits := api.ToBinary(c.Indices[i], len(c.Paths[i]))
		for level, sibling := range c.Paths[i] {
			left := api.Select(bits[level], sibling, leaf)
			right := api.Select(bits[level], leaf, sibling)
			leaf = gadget.PoseidonHash(api, []frontend.Variable{left, right})
		}
		if i == 0 {
			common = leaf
		} else {
			api.AssertIsEqual(leaf, common)
		}
	}
	if len(c.UpperPath) > 0 {
		bits := api.ToBinary(c.UpperIndex, len(c.UpperPath))
		for i, sibling := range c.UpperPath {
			common = gadget.PoseidonHash(api, []frontend.Variable{api.Select(bits[i], sibling, common), api.Select(bits[i], common, sibling)})
		}
	}
	api.AssertIsEqual(common, c.Root)
	return nil
}

func hash(values ...*big.Int) *big.Int {
	h, err := poseidon.Hash(values)
	if err != nil {
		panic(err)
	}
	return h
}

func fixture(n, occupiedHeight int) (*dagCircuit, *pathCircuit) {
	dag, paths := newDAG(n, occupiedHeight), newPaths(n)
	rng := rand.New(rand.NewSource(7201))
	indices := make([]uint32, 0, n)
	seen := make(map[uint32]bool)
	for len(indices) < n {
		index := rng.Uint32() >> (32 - occupiedHeight)
		if !seen[index] {
			indices, seen[index] = append(indices, index), true
		}
	}
	empty := make([]*big.Int, depth+1)
	empty[0] = big.NewInt(0)
	for i := 1; i <= depth; i++ {
		empty[i] = hash(empty[i-1], empty[i-1])
	}
	nodes := make([]map[uint32]*big.Int, depth+1)
	nodes[0] = make(map[uint32]*big.Int)
	for i, index := range indices {
		nodes[0][index] = hash(big.NewInt(int64(i+1)), big.NewInt(779))
		dag.Leaves[i], paths.Leaves[i], paths.Indices[i] = nodes[0][index], nodes[0][index], index
	}
	get := func(level int, index uint32) *big.Int {
		if node, ok := nodes[level][index]; ok {
			return node
		}
		if level >= occupiedHeight {
			return empty[level]
		}
		return hash(big.NewInt(991), new(big.Int).SetUint64(uint64(index)), big.NewInt(int64(level)))
	}
	positions := make([][]uint32, depth)
	row := make([]map[uint32]int, depth)
	for level := 0; level < depth; level++ {
		nodes[level+1] = make(map[uint32]*big.Int)
		for index := range nodes[level] {
			parent := index >> 1
			nodes[level+1][parent] = hash(get(level, parent*2), get(level, parent*2+1))
		}
		for index := range nodes[level+1] {
			positions[level] = append(positions[level], index)
		}
		sort.Slice(positions[level], func(i, j int) bool { return positions[level][i] < positions[level][j] })
		row[level] = make(map[uint32]int)
		for i, index := range positions[level] {
			row[level][index] = i
		}
	}
	for level := range dag.Levels {
		for i := range dag.Levels[level] {
			index := positions[level][i%len(positions[level])]
			parent := 0
			if level < depth-1 {
				parent = row[level+1][index>>1]*2 + int(index&1)
			}
			dag.Levels[level][i] = pair{Left: get(level, index*2), Right: get(level, index*2+1), Parent: parent}
		}
	}
	for i, index := range indices {
		dag.LeafRef[i] = row[0][index>>1]*2 + int(index&1)
		for level := range paths.Paths[i] {
			paths.Paths[i][level] = get(level, (index>>level)^1)
		}
	}
	paths.UpperIndex = 0
	dag.Root, paths.Root = nodes[depth][0], nodes[depth][0]
	dag.Salt, paths.Salt = 91827, 91827
	dag.Digest = leafDigest(dag.Leaves)
	paths.Digest = dag.Digest
	return dag, paths
}

func sharedPrefix(full *pathCircuit, height int) *pathCircuit {
	c := newPaths(len(full.Leaves))
	c.statement = full.statement
	c.UpperIndex = full.Indices[0].(uint32) >> height
	c.UpperPath = full.Paths[0][height:]
	for i := range c.Paths {
		c.Paths[i] = full.Paths[i][:height]
		c.Indices[i] = full.Indices[i].(uint32) & uint32((uint64(1)<<height)-1)
	}
	return c
}

func newPrefix(n, height int) *pathCircuit {
	c := newPaths(n)
	c.UpperPath = make([]frontend.Variable, depth-height)
	for i := range c.Paths {
		c.Paths[i] = c.Paths[i][:height]
	}
	return c
}

func leafDigest(leaves []frontend.Variable) *big.Int {
	values := []*big.Int{big.NewInt(91827)}
	for _, leaf := range leaves {
		values = append(values, leaf.(*big.Int))
	}
	digest, err := protocol.HashChain4(values)
	if err != nil {
		panic(err)
	}
	return digest
}

func TestPrivateDAG(t *testing.T) {
	for _, height := range []int{12, 32} {
		witness, paths := fixture(8, height)
		for _, item := range []struct{ circuit, witness frontend.Circuit }{{newDAG(8, height), witness}, {newPaths(8), paths}, {newPrefix(8, height), sharedPrefix(paths, height)}} {
			if err := test.IsSolved(item.circuit, item.witness, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		}
		for _, mutate := range []func(*dagCircuit){
			func(c *dagCircuit) { c.Root = 1 },
			func(c *dagCircuit) { c.Digest = 1 },
			func(c *dagCircuit) {
				c.Leaves[0] = big.NewInt(1)
				c.Digest = leafDigest(c.Leaves)
			},
			func(c *dagCircuit) { c.Levels[0][0].Left = 1 },
			func(c *dagCircuit) { c.Levels[0][0].Parent = 99999 },
			func(c *dagCircuit) { c.Levels[5][0].Parent = c.Levels[5][0].Parent.(int) ^ 1 },
			func(c *dagCircuit) { c.LeafRef[0] = 99999 },
			func(c *dagCircuit) { c.LeafRef[0] = c.LeafRef[1] },
		} {
			bad, _ := fixture(8, height)
			mutate(bad)
			if test.IsSolved(newDAG(8, height), bad, ecc.BN254.ScalarField()) == nil {
				t.Fatal("accepted tampered membership witness")
			}
		}
		duplicate, _ := fixture(8, height)
		duplicate.Leaves[0], duplicate.LeafRef[0] = duplicate.Leaves[1], duplicate.LeafRef[1]
		duplicate.Digest = leafDigest(duplicate.Leaves)
		if err := test.IsSolved(newDAG(8, height), duplicate, ecc.BN254.ScalarField()); err != nil {
			t.Fatal("membership permits duplicates; the payment must reject duplicate nullifiers", err)
		}

	}
}

func TestProving(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("DAG_INPUTS"))
	if n == 0 {
		t.Skip("set DAG_INPUTS")
	}
	height, _ := strconv.Atoi(os.Getenv("DAG_HEIGHT"))
	if height == 0 {
		height = 20
	}
	dag, paths := fixture(n, height)
	for _, item := range []struct {
		name             string
		circuit, witness frontend.Circuit
	}{{"paths", newPaths(n), paths}, {"shared_prefix", newPrefix(n, height), sharedPrefix(paths, height)}, {"private_dag", newDAG(n, height), dag}} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, item.circuit)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("DAG_COMPILE name=%s inputs=%d height=%d constraints=%d", item.name, n, height, ccs.GetNbConstraints())
		if os.Getenv("DAG_COMPILE_ONLY") == "1" {
			continue
		}
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			t.Fatal(err)
		}
		w, err := frontend.NewWitness(item.witness, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		public, _ := w.Public()
		for trial := 0; trial < 3; trial++ {
			start := time.Now()
			proof, err := groth16.Prove(ccs, pk, w)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if err = groth16.Verify(proof, vk, public); err != nil {
				t.Fatal(err)
			}
			t.Logf("DAG_PROVE name=%s inputs=%d height=%d trial=%d milliseconds=%.3f", item.name, n, height, trial, float64(elapsed.Microseconds())/1000)
		}
	}
}
