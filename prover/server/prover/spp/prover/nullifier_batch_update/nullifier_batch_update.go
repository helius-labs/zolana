package nullifierbatchupdate

import (
	"encoding/json"
	"fmt"
	"light/light-prover/prover/common"
	nullifiercircuit "light/light-prover/prover/spp/circuit/nullifier_batch_update"
	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

const NullifierBatchUpdateCircuitType = common.SppNullifierUpdateCircuitType

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
	return nullifiercircuit.Compile(treeHeight, batchSize)
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
	if treeHeight != protocol.NullifierTreeHeight {
		return nil, fmt.Errorf("spp nullifier update: tree height %d does not match SPP nullifier height %d", treeHeight, protocol.NullifierTreeHeight)
	}
	if len(request.NewEntries) != int(batchSize) {
		return nil, fmt.Errorf("spp nullifier update: new_entries length %d does not match batch size %d", len(request.NewEntries), batchSize)
	}
	tree, err := protocol.NewNullifierTree()
	if err != nil {
		return nil, fmt.Errorf("new nullifier tree: %w", err)
	}
	for i, entry := range request.ExistingEntries {
		value, err := parse.Field(entry)
		if err != nil {
			return nil, fmt.Errorf("existing_entries[%d]: %w", i, err)
		}
		if err := tree.Insert(value); err != nil {
			return nil, fmt.Errorf("existing_entries[%d]: %w", i, err)
		}
	}

	oldRoot := tree.Root()
	startIndex := tree.NextIndex()
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
		value, err := parse.Field(entry)
		if err != nil {
			return nil, fmt.Errorf("new_entries[%d]: %w", i, err)
		}
		witness, err := tree.InsertWithWitness(value, int(treeHeight))
		if err != nil {
			return nil, fmt.Errorf("new_entries[%d]: %w", i, err)
		}
		newValues[i] = value
		lowValues[i] = witness.LowValue
		lowNextValues[i] = witness.NextValue
		lowIndices[i] = new(big.Int).SetUint64(witness.LowIndex)
		lowProofs[i] = witness.LowElementProof
		newProofs[i] = witness.NewElementProof
	}

	hashchain, err := protocol.HashChain(newValues)
	if err != nil {
		return nil, err
	}
	startIndexField := new(big.Int).SetUint64(startIndex)
	publicInputHash, err := protocol.HashChain([]*big.Int{
		oldRoot,
		tree.Root(),
		hashchain,
		startIndexField,
	})
	if err != nil {
		return nil, err
	}

	return &nullifierBatchUpdateAssignment{
		oldRoot:              oldRoot,
		newRoot:              tree.Root(),
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

func (a *nullifierBatchUpdateAssignment) toCircuit(treeHeight, batchSize uint32) *nullifiercircuit.Circuit {
	circuit := nullifiercircuit.NewCircuit(treeHeight, batchSize)
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

func proofTrimTrailingZeroHexes(values []*big.Int) []string {
	end := len(values)
	for end > 0 && values[end-1].Sign() == 0 {
		end--
	}
	out := make([]string, end)
	for i := 0; i < end; i++ {
		out[i] = common.ToHex(values[i])
	}
	return out
}
