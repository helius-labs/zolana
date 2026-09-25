package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	merkletree "zolana/prover/merkle-tree"
	"zolana/prover/prover/common"
	nullifiertree "zolana/prover/prover/nullifier_tree"
	"zolana/prover/prover/timing"
	"zolana/prover/prover/transcript"
)

type BatchRequest struct {
	PreviousBatches []string           `json:"previousBatches,omitempty"`
	CircuitType     common.CircuitType `json:"circuitType"`
	Tree            string             `json:"tree"`
	TreeHeight      uint32             `json:"treeHeight"`
	BatchSize       uint32             `json:"batchSize"`
	StartIndex      uint64             `json:"startIndex"`
	AnchorIndex     uint64             `json:"anchorIndex"`
	AnchorRoot      string             `json:"anchorRoot"`
	HashchainHash   string             `json:"hashchainHash"`
	MinContextSlot  uint64             `json:"minContextSlot,omitempty"`
}

type batchLeaf struct{ value, next *big.Int }
type batchTree struct {
	tree   merkletree.PoseidonTree
	leaves []batchLeaf
	order  []int
}

var ErrIndexerNotReady = errors.New("indexer proof data not ready")

type batchCache struct {
	chains  []string
	address string
	tree    *batchTree
	latest  *batchTree
}

type batchReplay struct {
	address string
	index   uint64
	root    string
	tree    *batchTree
}

type queuePage struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Elements []struct {
		Seq   uint64 `json:"seq"`
		Value Hash   `json:"value"`
	} `json:"elements"`
}

func decodeBatch(data []byte) (BatchRequest, error) {
	var request BatchRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if len(data) > 1<<20 || decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		return request, fmt.Errorf("invalid indexed batch")
	}
	if request.CircuitType != common.BatchAddressAppendCircuitType || request.TreeHeight != 40 || (request.BatchSize != 10 && request.BatchSize != 250) || request.AnchorIndex == 0 || request.StartIndex < request.AnchorIndex || request.StartIndex > (1<<40)-uint64(request.BatchSize) {
		return request, fmt.Errorf("invalid indexed batch bounds")
	}
	if _, err := decodeHash(request.Tree); err != nil {
		return request, err
	}
	distance := request.StartIndex - request.AnchorIndex
	if distance%uint64(request.BatchSize) != 0 || uint64(len(request.PreviousBatches)) != distance/uint64(request.BatchSize) {
		return request, fmt.Errorf("invalid preceding batch commitments")
	}
	for _, value := range append([]string{request.AnchorRoot, request.HashchainHash}, request.PreviousBatches...) {
		field, err := common.FeFromHex(value)
		if err != nil || value == "" {
			return request, fmt.Errorf("invalid batch commitment")
		}
		if _, err := hashField(field); err != nil {
			return request, err
		}
	}
	return request, nil
}

func newBatchTree(height uint32) (*batchTree, error) {
	maximum := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	tree := &batchTree{tree: merkletree.NewTree(int(height)), leaves: []batchLeaf{{new(big.Int), maximum}}, order: []int{0}}
	leaf, err := transcript.HashFields([]*big.Int{new(big.Int), maximum})
	if err != nil {
		return nil, err
	}
	tree.tree.Update(0, *leaf)
	return tree, nil
}

func (t *batchTree) fork() *batchTree {
	// 1. Forks share immutable Merkle nodes.
	return &batchTree{tree: t.tree, leaves: slices.Clone(t.leaves), order: slices.Clone(t.order)}
}

func (t *batchTree) append(value *big.Int, params *nullifiertree.BatchAddressAppendParameters) error {
	position, exists := slices.BinarySearchFunc(t.order, value, func(index int, value *big.Int) int { return t.leaves[index].value.Cmp(value) })
	if exists || position == 0 {
		return fmt.Errorf("duplicate or invalid queued nullifier")
	}
	lowIndex := t.order[position-1]
	low := t.leaves[lowIndex]
	if value.Cmp(low.next) >= 0 {
		return fmt.Errorf("queued nullifier exceeds range")
	}
	index := len(t.leaves)
	if params != nil {
		params.LowElementValues = append(params.LowElementValues, *low.value)
		params.LowElementIndices = append(params.LowElementIndices, *big.NewInt(int64(lowIndex)))
		params.LowElementNextValues = append(params.LowElementNextValues, *low.next)
		params.LowElementProofs = append(params.LowElementProofs, t.tree.GenerateProof(lowIndex))
		params.NewElementValues = append(params.NewElementValues, *value)
	}
	lowHash, err := transcript.HashFields([]*big.Int{low.value, value})
	if err != nil {
		return err
	}
	newHash, err := transcript.HashFields([]*big.Int{value, low.next})
	if err != nil {
		return err
	}
	t.tree.Update(lowIndex, *lowHash)
	if params != nil {
		params.NewElementProofs = append(params.NewElementProofs, t.tree.GenerateProof(index))
	}
	t.tree.Update(index, *newHash)
	t.leaves[lowIndex] = batchLeaf{low.value, value}
	t.leaves = append(t.leaves, batchLeaf{value, low.next})
	t.order = slices.Insert(t.order, position, index)
	return nil
}

func (r *Resolver) resolveBatch(ctx context.Context, data []byte) (result *Resolved, err error) {
	// Not ready only after this call stored a replay checkpoint.
	var checkpointed bool
	defer func() {
		if err != nil && checkpointed && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = ErrIndexerNotReady
		}
	}()
	request, err := decodeBatch(data)
	if err != nil {
		return nil, err
	}
	if request.StartIndex+uint64(request.BatchSize) > r.maxBatchLeaves {
		return nil, fmt.Errorf("batch replay exceeds configured leaf limit")
	}
	select {
	case r.batchLock <- struct{}{}:
		defer func() { <-r.batchLock }()
	case <-ctx.Done():
		return nil, ErrIndexerNotReady
	}
	finish := timing.FromContext(ctx).Start("indexer_batch_prepare")
	defer finish()
	anchor, _ := common.FeFromHex(request.AnchorRoot)
	chain, _ := common.FeFromHex(request.HashchainHash)
	base := r.batch.tree
	if r.batch.address != request.Tree || base == nil || uint64(len(base.leaves)) > request.AnchorIndex {
		base, err = newBatchTree(request.TreeHeight)
		if err != nil {
			return nil, err
		}
	}
	if latest := r.batch.latest; r.batch.address == request.Tree && latest != nil && uint64(len(latest.leaves)) <= request.AnchorIndex && len(latest.leaves) > len(base.leaves) {
		base = latest
	}
	if replay := r.batchReplay; replay.address == request.Tree && replay.index == request.AnchorIndex && replay.root == request.AnchorRoot && replay.tree != nil && len(replay.tree.leaves) > len(base.leaves) {
		base = replay.tree
	}
	tree := base.fork()
	replayed := uint64(0)
	end := request.StartIndex + uint64(request.BatchSize)
	params := &nullifiertree.BatchAddressAppendParameters{TreeHeight: request.TreeHeight, BatchSize: request.BatchSize, StartIndex: request.StartIndex, HashchainHash: chain}
	anchored := false
	var preceding []*big.Int
	for next := uint64(len(tree.leaves)); next < end; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if next == request.AnchorIndex && !anchored {
			root := tree.tree.Root.Value()
			if root.Cmp(anchor) != 0 {
				r.batch = batchCache{}
				r.batchReplay = batchReplay{}
				return nil, ErrIndexerNotReady
			}
			latest := r.batch.latest
			chains := r.batch.chains
			sameTree := r.batch.address == request.Tree && r.batch.tree != nil && uint64(len(r.batch.tree.leaves)) == request.AnchorIndex
			if sameTree {
				previousRoot := r.batch.tree.tree.Root.Value()
				sameTree = previousRoot.Cmp(anchor) == 0
			}
			r.batch = batchCache{address: request.Tree, tree: tree.fork()}
			r.batchReplay = batchReplay{}
			anchored = true
			if sameTree && latest != nil && uint64(len(latest.leaves)) >= next && uint64(len(latest.leaves)) <= request.StartIndex && len(chains) <= len(request.PreviousBatches) && slices.Equal(chains, request.PreviousBatches[:len(chains)]) {
				tree = latest.fork()
				next = uint64(len(tree.leaves))
			}
		}
		limit := min(uint64(1000), end-next)
		if next < request.AnchorIndex {
			limit = min(limit, request.AnchorIndex-next)
		}
		body, err := r.rpc(ctx, "getNullifierQueueElements", struct {
			Tree  string `json:"treeAccount"`
			Start uint64 `json:"startSeq"`
			Limit uint64 `json:"limit"`
		}{request.Tree, next, limit})
		if err != nil {
			return nil, err
		}
		var page queuePage
		if json.Unmarshal(body, &page) != nil || uint64(len(page.Elements)) > limit {
			return nil, fmt.Errorf("invalid indexer batch page")
		}
		if page.Context.Slot < request.MinContextSlot || uint64(len(page.Elements)) < limit {
			return nil, ErrIndexerNotReady
		}
		for _, element := range page.Elements {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if element.Seq != next {
				return nil, fmt.Errorf("indexer batch sequence mismatch")
			}
			value, err := element.Value.field()
			if err != nil {
				return nil, err
			}
			var target *nullifiertree.BatchAddressAppendParameters
			if next >= request.StartIndex {
				target = params
			}
			if next == request.StartIndex {
				root := tree.tree.Root.Value()
				params.OldRoot = new(big.Int).Set(&root)
			}
			if err := tree.append(value, target); err != nil {
				return nil, err
			}
			if next >= request.AnchorIndex && next < request.StartIndex {
				preceding = append(preceding, value)
				if len(preceding) == int(request.BatchSize) {
					batch := (next - request.AnchorIndex) / uint64(request.BatchSize)
					expected, _ := common.FeFromHex(request.PreviousBatches[batch])
					actual, err := transcript.HashChain4(preceding)
					if err != nil || actual.Cmp(expected) != 0 {
						return nil, ErrIndexerNotReady
					}
					preceding = nil
				}
			}
			next++
		}
		if !anchored {
			r.batchReplay = batchReplay{address: request.Tree, index: request.AnchorIndex, root: request.AnchorRoot, tree: tree.fork()}
			checkpointed = true
			replayed += limit
			if replayed >= 4096 && next < request.AnchorIndex {
				return nil, ErrIndexerNotReady
			}
		}
	}
	if !anchored {
		return nil, fmt.Errorf("missing batch anchor")
	}
	// 2. The queue commitment fixes every value and its insertion order.
	values := make([]*big.Int, len(params.NewElementValues))
	for i := range values {
		values[i] = &params.NewElementValues[i]
	}
	computed, err := transcript.HashChain4(values)
	if err != nil || computed.Cmp(chain) != 0 {
		return nil, fmt.Errorf("indexer batch hash mismatch")
	}
	r.batch.latest = tree.fork()
	r.batch.chains = append(slices.Clone(request.PreviousBatches), request.HashchainHash)
	root := tree.tree.Root.Value()
	params.NewRoot = new(big.Int).Set(&root)
	params.PublicInputHash, err = transcript.HashChain4([]*big.Int{params.OldRoot, params.NewRoot, chain, new(big.Int).SetUint64(request.StartIndex)})
	if err != nil {
		return nil, err
	}
	payload, err := params.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return &Resolved{Payload: payload, Resolution: &common.ProofResolution{
		PublicInputHash: common.FeHex(params.PublicInputHash),
		Batch:           &common.ResolvedBatch{Tree: request.Tree, StartIndex: request.StartIndex, OldRoot: common.FeHex(params.OldRoot), NewRoot: common.FeHex(params.NewRoot)},
	}}, nil
}

func batchCircuit(data []byte) bool {
	var meta struct {
		Circuit common.CircuitType `json:"circuitType"`
	}
	return json.Unmarshal(data, &meta) == nil && meta.Circuit == common.BatchAddressAppendCircuitType
}
