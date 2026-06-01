package spp

import (
	"encoding/json"
	"fmt"
	"light/light-prover/prover/common"
	"light/light-prover/prover/poseidon"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const NullifierBatchUpdateCircuitType = common.SppNullifierUpdateCircuitType

type NullifierBatchUpdateCircuit struct {
	TreeHeight uint32 `gnark:"-"`
	BatchSize  uint32 `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot       frontend.Variable
	NewRoot       frontend.Variable
	HashchainHash frontend.Variable
	StartIndex    frontend.Variable

	LowElementValues     []frontend.Variable
	LowElementNextValues []frontend.Variable
	LowElementIndices    []frontend.Variable
	LowElementProofs     [][]frontend.Variable

	NewElementValues []frontend.Variable
	NewElementProofs [][]frontend.Variable
}

type NullifierBatchUpdateRequest struct {
	ExistingEntries []string `json:"existing_entries"`
	NewEntries      []string `json:"new_entries"`
}

type NullifierBatchUpdateBundle struct {
	Proof           *common.Proof `json:"proof"`
	OldRoot         string        `json:"old_root"`
	NewRoot         string        `json:"new_root"`
	HashchainHash   string        `json:"hashchain_hash"`
	StartIndex      uint64        `json:"start_index"`
	PublicInputHash string        `json:"public_input_hash"`
	NewEntries      []string      `json:"new_entries"`
}

type nullifierBatchUpdateAssignment struct {
	oldRoot              *big.Int
	newRoot              *big.Int
	hashchainHash        *big.Int
	startIndex           uint64
	publicInputHash      *big.Int
	lowElementValues     []*big.Int
	lowElementNextValues []*big.Int
	lowElementIndices    []*big.Int
	lowElementProofs     [][]*big.Int
	newElementValues     []*big.Int
	newElementProofs     [][]*big.Int
}

func NewNullifierBatchUpdateCircuit(treeHeight, batchSize uint32) *NullifierBatchUpdateCircuit {
	circuit := &NullifierBatchUpdateCircuit{
		TreeHeight:           treeHeight,
		BatchSize:            batchSize,
		LowElementValues:     make([]frontend.Variable, batchSize),
		LowElementNextValues: make([]frontend.Variable, batchSize),
		LowElementIndices:    make([]frontend.Variable, batchSize),
		LowElementProofs:     make([][]frontend.Variable, batchSize),
		NewElementValues:     make([]frontend.Variable, batchSize),
		NewElementProofs:     make([][]frontend.Variable, batchSize),
	}
	for i := uint32(0); i < batchSize; i++ {
		circuit.LowElementProofs[i] = make([]frontend.Variable, treeHeight)
		circuit.NewElementProofs[i] = make([]frontend.Variable, treeHeight)
	}
	return circuit
}

func (c *NullifierBatchUpdateCircuit) Define(api frontend.API) error {
	currentRoot := c.OldRoot
	for i := uint32(0); i < c.BatchSize; i++ {
		oldLowLeaf := IndexedLeafHashCircuit(api, c.LowElementValues[i], c.LowElementNextValues[i])
		newLowLeaf := IndexedLeafHashCircuit(api, c.LowElementValues[i], c.NewElementValues[i])

		// Strict ordering low < new < next without a `+1` increment, so the
		// comparison cannot wrap at the field boundary.
		api.AssertIsLessOrEqual(c.LowElementValues[i], c.NewElementValues[i])
		api.AssertIsDifferent(c.LowElementValues[i], c.NewElementValues[i])
		api.AssertIsLessOrEqual(c.NewElementValues[i], c.LowElementNextValues[i])
		api.AssertIsDifferent(c.NewElementValues[i], c.LowElementNextValues[i])

		lowIndexBits := api.ToBinary(c.LowElementIndices[i], int(c.TreeHeight))
		oldLowRoot := StatePathFoldCircuit(api, oldLowLeaf, c.LowElementProofs[i], lowIndexBits)
		api.AssertIsEqual(oldLowRoot, currentRoot)
		currentRoot = StatePathFoldCircuit(api, newLowLeaf, c.LowElementProofs[i], lowIndexBits)

		newLeaf := IndexedLeafHashCircuit(api, c.NewElementValues[i], c.LowElementNextValues[i])
		newIndexBits := api.ToBinary(api.Add(c.StartIndex, i), int(c.TreeHeight))
		emptyRoot := StatePathFoldCircuit(api, frontend.Variable(0), c.NewElementProofs[i], newIndexBits)
		api.AssertIsEqual(emptyRoot, currentRoot)
		currentRoot = StatePathFoldCircuit(api, newLeaf, c.NewElementProofs[i], newIndexBits)
	}

	api.AssertIsEqual(c.NewRoot, currentRoot)
	api.AssertIsEqual(c.HashchainHash, QueueHashChainCircuit(api, c.NewElementValues))
	api.AssertIsEqual(
		c.PublicInputHash,
		QueueHashChainCircuit(api, []frontend.Variable{
			c.OldRoot,
			c.NewRoot,
			c.HashchainHash,
			c.StartIndex,
		}),
	)
	return nil
}

func SetupNullifierBatchUpdate(treeHeight, batchSize uint32) (*common.BatchProofSystem, error) {
	ccs, err := CompileNullifierBatchUpdate(treeHeight, batchSize)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.BatchProofSystem{
		CircuitType:      NullifierBatchUpdateCircuitType,
		TreeHeight:       treeHeight,
		BatchSize:        batchSize,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func CompileNullifierBatchUpdate(treeHeight, batchSize uint32) (constraint.ConstraintSystem, error) {
	if treeHeight != NullifierTreeHeight {
		return nil, fmt.Errorf("spp nullifier update: tree height %d does not match SPP nullifier height %d", treeHeight, NullifierTreeHeight)
	}
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		NewNullifierBatchUpdateCircuit(treeHeight, batchSize),
		frontend.WithCompressThreshold(300),
	)
}

func WriteNullifierBatchUpdateBundle(ps *common.BatchProofSystem, requestPath string, outputPath string) error {
	bytes, err := os.ReadFile(requestPath)
	if err != nil {
		return err
	}
	var request NullifierBatchUpdateRequest
	if err := json.Unmarshal(bytes, &request); err != nil {
		return err
	}
	bundle, err := BuildNullifierBatchUpdateBundle(ps, request)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(outputPath, out, 0644)
}

func BuildNullifierBatchUpdateBundle(ps *common.BatchProofSystem, request NullifierBatchUpdateRequest) (*NullifierBatchUpdateBundle, error) {
	assignmentData, err := buildNullifierBatchUpdateAssignment(ps.TreeHeight, ps.BatchSize, request)
	if err != nil {
		return nil, err
	}
	assignment := assignmentData.toCircuit(ps.TreeHeight, ps.BatchSize)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, err
	}
	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, err
	}
	if err := groth16.Verify(proof, ps.VerifyingKey, publicWitness); err != nil {
		return nil, err
	}

	return &NullifierBatchUpdateBundle{
		Proof:           &common.Proof{Proof: proof},
		OldRoot:         common.ToHex(assignmentData.oldRoot),
		NewRoot:         common.ToHex(assignmentData.newRoot),
		HashchainHash:   common.ToHex(assignmentData.hashchainHash),
		StartIndex:      assignmentData.startIndex,
		PublicInputHash: common.ToHex(assignmentData.publicInputHash),
		NewEntries:      proofTrimTrailingZeroHexes(assignmentData.newElementValues),
	}, nil
}

func buildNullifierBatchUpdateAssignment(treeHeight, batchSize uint32, request NullifierBatchUpdateRequest) (*nullifierBatchUpdateAssignment, error) {
	if treeHeight != NullifierTreeHeight {
		return nil, fmt.Errorf("spp nullifier update: tree height %d does not match SPP nullifier height %d", treeHeight, NullifierTreeHeight)
	}
	if len(request.NewEntries) != int(batchSize) {
		return nil, fmt.Errorf("spp nullifier update: new_entries length %d does not match batch size %d", len(request.NewEntries), batchSize)
	}
	tree := NewIndexedTree()
	for i, entry := range request.ExistingEntries {
		value, err := parseField(entry)
		if err != nil {
			return nil, fmt.Errorf("existing_entries[%d]: %w", i, err)
		}
		if err := tree.InsertChecked(value); err != nil {
			return nil, fmt.Errorf("existing_entries[%d]: %w", i, err)
		}
	}

	oldRoot := new(big.Int).Set(tree.Root)
	startIndex := uint64(len(tree.Elements))
	if startIndex+uint64(batchSize) > 1<<treeHeight {
		return nil, fmt.Errorf("spp nullifier update: batch exceeds tree capacity")
	}

	newValues := make([]*big.Int, batchSize)
	lowValues := make([]*big.Int, batchSize)
	lowNextValues := make([]*big.Int, batchSize)
	lowIndices := make([]*big.Int, batchSize)
	lowProofs := make([][]*big.Int, batchSize)
	newProofs := make([][]*big.Int, batchSize)

	for i, entry := range request.NewEntries {
		value, err := parseField(entry)
		if err != nil {
			return nil, fmt.Errorf("new_entries[%d]: %w", i, err)
		}
		witness, err := tree.insertWithBatchWitness(value, int(treeHeight))
		if err != nil {
			return nil, fmt.Errorf("new_entries[%d]: %w", i, err)
		}
		newValues[i] = value
		lowValues[i] = witness.LowValue
		lowNextValues[i] = witness.NextValue
		lowIndices[i] = new(big.Int).SetUint64(witness.LowIndex)
		lowProofs[i] = witness.LowSiblings
		newProofs[i] = witness.NewSiblings
	}

	hashchain, err := QueueHashChain(newValues)
	if err != nil {
		return nil, err
	}
	startIndexField := new(big.Int).SetUint64(startIndex)
	publicInputHash, err := QueueHashChain([]*big.Int{
		oldRoot,
		tree.Root,
		hashchain,
		startIndexField,
	})
	if err != nil {
		return nil, err
	}

	return &nullifierBatchUpdateAssignment{
		oldRoot:              oldRoot,
		newRoot:              new(big.Int).Set(tree.Root),
		hashchainHash:        hashchain,
		startIndex:           startIndex,
		publicInputHash:      publicInputHash,
		lowElementValues:     lowValues,
		lowElementNextValues: lowNextValues,
		lowElementIndices:    lowIndices,
		lowElementProofs:     lowProofs,
		newElementValues:     newValues,
		newElementProofs:     newProofs,
	}, nil
}

type nullifierBatchInsertWitness struct {
	LowValue    *big.Int
	LowIndex    uint64
	NextValue   *big.Int
	LowSiblings []*big.Int
	NewSiblings []*big.Int
}

func (t *IndexedTree) insertWithBatchWitness(value *big.Int, height int) (nullifierBatchInsertWitness, error) {
	if value.Sign() <= 0 || value.Cmp(highestNullifierPlusOne) >= 0 {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: indexed tree value out of range: %s", value)
	}
	newIndex := uint64(len(t.Elements))
	if height < 64 && newIndex >= 1<<height {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: new nullifier index %d exceeds 2^%d", newIndex, height)
	}

	low, err := t.lowElementForNonInclusion(value)
	if err != nil {
		return nullifierBatchInsertWitness{}, err
	}
	nextValue, err := t.elementNextValue(low)
	if err != nil {
		return nullifierBatchInsertWitness{}, err
	}
	if nextValue.Cmp(value) <= 0 {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: indexed tree value already present or outside low range: %s", value)
	}

	entries := make(map[uint64]*big.Int, len(t.LeafHashes))
	for index, leaf := range t.LeafHashes {
		entries[index] = new(big.Int).Set(leaf)
	}
	_, oldProofs := buildSparseBinaryStateTree(entries, height)
	lowProof, ok := oldProofs[low.Index]
	if !ok {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: missing indexed tree low-element proof")
	}

	afterLow := make(map[uint64]*big.Int, len(t.LeafHashes)+1)
	for index, leaf := range t.LeafHashes {
		afterLow[index] = new(big.Int).Set(leaf)
	}
	afterLow[low.Index] = IndexedLeafHash(low.Value, value)
	afterLow[newIndex] = new(big.Int)
	_, afterLowProofs := buildSparseBinaryStateTree(afterLow, height)
	newProof, ok := afterLowProofs[newIndex]
	if !ok {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: missing empty new-leaf proof")
	}

	if err := t.InsertChecked(value); err != nil {
		return nullifierBatchInsertWitness{}, err
	}

	return nullifierBatchInsertWitness{
		LowValue:    new(big.Int).Set(low.Value),
		LowIndex:    low.Index,
		NextValue:   new(big.Int).Set(nextValue),
		LowSiblings: lowProof.Siblings,
		NewSiblings: newProof.Siblings,
	}, nil
}

func (a *nullifierBatchUpdateAssignment) toCircuit(treeHeight, batchSize uint32) *NullifierBatchUpdateCircuit {
	circuit := NewNullifierBatchUpdateCircuit(treeHeight, batchSize)
	circuit.PublicInputHash = a.publicInputHash
	circuit.OldRoot = a.oldRoot
	circuit.NewRoot = a.newRoot
	circuit.HashchainHash = a.hashchainHash
	circuit.StartIndex = new(big.Int).SetUint64(a.startIndex)
	for i := 0; i < int(batchSize); i++ {
		circuit.LowElementValues[i] = a.lowElementValues[i]
		circuit.LowElementNextValues[i] = a.lowElementNextValues[i]
		circuit.LowElementIndices[i] = a.lowElementIndices[i]
		circuit.NewElementValues[i] = a.newElementValues[i]
		for j := 0; j < int(treeHeight); j++ {
			circuit.LowElementProofs[i][j] = a.lowElementProofs[i][j]
			circuit.NewElementProofs[i][j] = a.newElementProofs[i][j]
		}
	}
	return circuit
}

// QueueHashChain matches Light's batched queue hash-chain convention:
//
//	h = inputs[0]
//	for i = 1; i < len(inputs); i++:
//	    h = Poseidon(h, inputs[i])
//
// The SPP transaction circuit uses a right-folded hash chain for spec public
// inputs. Nullifier batch updates must use the queue convention because the
// proof binds to the exact hash_chain_stores value consumed from Light's
// address queue.
func QueueHashChain(inputs []*big.Int) (*big.Int, error) {
	if len(inputs) == 0 {
		return new(big.Int), nil
	}
	for i, input := range inputs {
		if err := validateFieldElement(fmt.Sprintf("input[%d]", i), input); err != nil {
			return nil, fmt.Errorf("spp: queue hash chain: %w", err)
		}
	}

	h := new(big.Int).Set(inputs[0])
	for i := 1; i < len(inputs); i++ {
		next, err := poseidon.HashWithT(3, []*big.Int{h, inputs[i]})
		if err != nil {
			return nil, fmt.Errorf("spp: queue hash chain step %d: %w", i, err)
		}
		h = next
	}
	return h, nil
}

func QueueHashChainCircuit(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}

	h := inputs[0]
	for i := 1; i < len(inputs); i++ {
		h = poseidon.HashCircuitWithT(api, 3, []frontend.Variable{h, inputs[i]})
	}
	return h
}
