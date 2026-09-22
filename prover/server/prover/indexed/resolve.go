package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"zolana/prover/prover/common"
	"zolana/prover/prover/timing"
	prooftranscript "zolana/prover/prover/transcript"

	"golang.org/x/sync/errgroup"
)

type Resolved struct {
	Payload    json.RawMessage
	Resolution *common.ProofResolution
}

type treeProofs struct {
	state      response[stateProof]
	exclusion  response[nullifierProof]
	inputs     []int
	realInputs []int
}

func Validate(data []byte) error {
	_, _, err := decodeRequest(data)
	return err
}

func decodeRequest(data []byte) (Request, *preparedProof, error) {
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if len(data) > 1<<20 || decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		return request, nil, fmt.Errorf("invalid indexed request")
	}
	if len(request.Trees) == 0 || len(request.Trees) > 2 {
		return request, nil, fmt.Errorf("invalid input tree count")
	}
	for index, tree := range request.Trees {
		if _, err := decodeHash(tree.Address); err != nil {
			return request, nil, fmt.Errorf("invalid tree address")
		}
		for _, previous := range request.Trees[:index] {
			if tree.ID == previous.ID || tree.Address == previous.Address {
				return request, nil, fmt.Errorf("duplicate input tree")
			}
		}
	}
	expected := 15
	switch request.CircuitType {
	case common.TransferRingAuthorityCircuitType:
		expected = 14
	case common.TransferP256RingCircuitType:
		expected = 17
	case common.MergeCircuitType:
		expected = 7
	case common.MergeRingCircuitType:
		expected = 8
	}
	if len(request.PublicInputs) != expected {
		return request, nil, fmt.Errorf("invalid public input count")
	}
	for _, encoded := range request.PublicInputs {
		field, err := common.FeFromHex(encoded)
		if err != nil || encoded == "" {
			return request, nil, fmt.Errorf("invalid public input")
		}
		if _, err := hashField(field); err != nil {
			return request, nil, err
		}
	}
	for index, input := range request.Inputs {
		if index > 0 && input.TreeSlot < request.Inputs[index-1].TreeSlot {
			return request, nil, fmt.Errorf("interleaved input trees")
		}
	}
	prepared, err := decodePrepared(request)
	return request, prepared, err
}

func (r *Resolver) resolve(ctx context.Context, data []byte) (*Resolved, error) {
	trace := timing.FromContext(ctx)
	finishDecode := trace.Start("indexer_decode")
	request, prepared, err := decodeRequest(data)
	finishDecode()
	if err != nil {
		return nil, err
	}
	finishAdmission := trace.Start("indexer_admission")
	defer finishAdmission()
	select {
	case r.permits <- struct{}{}:
		defer func() { <-r.permits }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	finishAdmission()
	finishFetch := trace.Start("indexer_fetch")
	defer finishFetch()
	proofs := make([]treeProofs, len(request.Trees))
	for index, input := range request.Inputs {
		group := &proofs[input.TreeSlot]
		group.inputs = append(group.inputs, index)
		if input.Commitment != nil {
			group.realInputs = append(group.realInputs, index)
		}
	}
	for _, group := range proofs {
		if len(group.realInputs) == 0 {
			return nil, fmt.Errorf("input tree has no real spend")
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// 1. Fetch one nullifier snapshot per tree for real and dummy inputs together.
	tasks, taskContext := errgroup.WithContext(ctx)
	for treeIndex, tree := range request.Trees {
		group := &proofs[treeIndex]
		leaves := make([]Hash, len(group.realInputs))
		for index, input := range group.realInputs {
			leaves[index] = *request.Inputs[input].Commitment
		}
		nullifiers := make([]Hash, len(group.inputs))
		for index, input := range group.inputs {
			prepared.inputs[input].nullifier.FillBytes(nullifiers[index][:])
		}
		tasks.Go(func() error {
			data, err := r.call(taskContext, proofQuery{Method: "getMerkleProofs", Tree: tree.Address, Leaves: leaves})
			if err != nil {
				return err
			}
			if json.Unmarshal(data, &group.state) != nil || group.state.Context.Slot < request.MinContextSlot {
				return fmt.Errorf("invalid state proof response")
			}
			return nil
		})
		tasks.Go(func() error {
			data, err := r.call(taskContext, proofQuery{Method: "getNonInclusionProofs", Tree: tree.Address, Leaves: nullifiers})
			if err != nil {
				return err
			}
			if json.Unmarshal(data, &group.exclusion) != nil || group.exclusion.Context.Slot < request.MinContextSlot {
				return fmt.Errorf("invalid nullifier proof response")
			}
			return nil
		})
	}
	if err := tasks.Wait(); err != nil {
		return nil, err
	}
	finishFetch()
	finishValidate := trace.Start("indexer_validate")
	defer finishValidate()
	// 2. Bind every returned path to its requested leaf before completing the inputs.
	resolution := &common.ProofResolution{Trees: make([]common.ResolvedTree, len(request.Trees))}
	slots := make([]common.TreeSlotParams, 5)
	for index := range slots {
		slots[index] = common.TreeSlotParams{ID: new(big.Int), UtxoRoot: new(big.Int), NullifierRoot: new(big.Int)}
	}
	for treeIndex, tree := range request.Trees {
		group := &proofs[treeIndex]
		if len(group.state.Proofs) != len(group.realInputs) || len(group.exclusion.Proofs) != len(group.inputs) {
			return nil, fmt.Errorf("indexer proof count mismatch")
		}
		stateRoot, nullifierRoot := group.state.Proofs[0], group.exclusion.Proofs[0]
		states := make(map[int]*stateProof, len(group.realInputs))
		for index, input := range group.realInputs {
			proof := &group.state.Proofs[index]
			if proof.Leaf != *request.Inputs[input].Commitment || proof.MerkleContext.Tree != tree.Address || proof.MerkleContext.TreeType != 1 || proof.Root != stateRoot.Root || proof.RootIndex != stateRoot.RootIndex || proof.RootSeq != stateRoot.RootSeq || len(proof.Path) != 32 {
				return nil, fmt.Errorf("state proof binding mismatch")
			}
			if err := verifyPath(proof.Leaf, proof.Path, proof.LeafIndex, proof.Root); err != nil {
				return nil, err
			}
			states[input] = proof
		}
		for index, input := range group.inputs {
			proof := group.exclusion.Proofs[index]
			expected, err := hashField(prepared.inputs[input].nullifier)
			if err != nil || proof.Leaf != expected || proof.MerkleContext.Tree != tree.Address || proof.MerkleContext.TreeType != 2 || proof.Root != nullifierRoot.Root || proof.RootIndex != nullifierRoot.RootIndex || proof.RootSeq != nullifierRoot.RootSeq || len(proof.Path) != 40 {
				return nil, fmt.Errorf("nullifier proof binding mismatch")
			}
			low, err := proof.LowElement.field()
			if err != nil {
				return nil, err
			}
			high, err := proof.HighElement.field()
			if err != nil || low.Cmp(prepared.inputs[input].nullifier) >= 0 || high.Cmp(prepared.inputs[input].nullifier) <= 0 {
				return nil, fmt.Errorf("invalid nullifier exclusion range")
			}
			leaf, err := prooftranscript.HashFields([]*big.Int{low, high})
			if err != nil {
				return nil, err
			}
			leafHash, err := hashField(leaf)
			if err != nil {
				return nil, err
			}
			if err := verifyPath(leafHash, proof.Path, proof.LowElementIndex, proof.Root); err != nil {
				return nil, err
			}
			prepared.inputs[input].apply(states[input], proof)
		}
		slots[treeIndex] = common.TreeSlotParams{ID: new(big.Int).SetUint64(uint64(tree.ID)), UtxoRoot: new(big.Int).SetBytes(stateRoot.Root[:]), NullifierRoot: new(big.Int).SetBytes(nullifierRoot.Root[:])}
		resolution.Trees[treeIndex] = common.ResolvedTree{Tree: tree.Address, ID: tree.ID, UtxoRoot: stateRoot.Root.hex(), NullifierRoot: nullifierRoot.Root.hex(), UtxoRootIndex: stateRoot.RootIndex, NullifierRootIndex: nullifierRoot.RootIndex}
	}
	// 3. Insert the resolved tree commitment into the circuit's public transcript.
	hashes := make([]*big.Int, len(slots))
	for index, slot := range slots {
		hashes[index], err = prooftranscript.HashFields([]*big.Int{slot.ID, slot.UtxoRoot, slot.NullifierRoot})
		if err != nil {
			return nil, err
		}
	}
	treeHash, err := prooftranscript.RightHashChain(hashes)
	if err != nil {
		return nil, err
	}
	public, err := common.FeFromHexSlice(request.PublicInputs)
	if err != nil {
		return nil, fmt.Errorf("invalid public input")
	}
	transcript := append([]*big.Int{}, public[:2]...)
	transcript = append(transcript, treeHash)
	transcript = append(transcript, public[2:]...)
	*prepared.hash, err = prooftranscript.HashChain4(transcript)
	if err != nil {
		return nil, err
	}
	*prepared.slots = slots
	resolution.PublicInputHash = common.FeHex(*prepared.hash)
	payload, err := prepared.value.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("cannot encode resolved inputs")
	}
	return &Resolved{Payload: payload, Resolution: resolution}, nil
}

func verifyPath(leaf Hash, path []Hash, index uint64, root Hash) error {
	if len(path) > 63 || index >= uint64(1)<<len(path) {
		return fmt.Errorf("invalid proof path index")
	}
	hash, err := leaf.field()
	if err != nil {
		return err
	}
	for level, sibling := range path {
		value, err := sibling.field()
		if err != nil {
			return err
		}
		pair := []*big.Int{hash, value}
		if index>>level&1 != 0 {
			pair[0], pair[1] = pair[1], pair[0]
		}
		hash, err = prooftranscript.HashFields(pair)
		if err != nil {
			return err
		}
	}
	if !bytes.Equal(hash.FillBytes(make([]byte, 32)), root[:]) {
		return fmt.Errorf("proof root mismatch")
	}
	return nil
}
