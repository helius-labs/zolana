package indexed

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/deposit"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	ring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
	"github.com/helius-labs/zolana/prover/server/prover/timing"
)

// decodeDeposit reads a deposit request without the registry keys the indexer supplies.
func decodeDeposit(data []byte) (Request, *ring.DepositParams, error) {
	request, err := decodeEnvelope(data)
	if err != nil {
		return request, nil, err
	}
	if request.CircuitType != common.CustomRingDepositCircuitType || len(request.Trees) != 0 || len(request.Inputs) != 0 || len(request.PublicInputs) != 1 {
		return request, nil, fmt.Errorf("invalid indexed deposit")
	}
	var params ring.DepositParams
	if ring.Unmarshal(request.Prepared, &params) != nil || params.Keys != nil {
		return request, nil, fmt.Errorf("invalid prepared deposit")
	}
	if err := validateRegistryAnchor(params.KeyRegistryRoot, request.Registry); err != nil {
		return request, nil, err
	}
	if params.Count < 1 || params.Count > deposit.MaxDeposits {
		return request, nil, fmt.Errorf("invalid deposit count")
	}
	params.Keys = make([]*ring.RegistryKey, deposit.MaxDeposits)
	if _, err := ring.Assign(request.CircuitType, &params); err != nil {
		return request, nil, fmt.Errorf("invalid prepared deposit: %w", err)
	}
	expected, err := common.FeFromHex(request.PublicInputs[0])
	if err != nil || !params.KeyEscrow || expected.Cmp(params.PublicInputHash.Int) != 0 {
		return request, nil, fmt.Errorf("deposit statement mismatch")
	}
	return request, &params, nil
}

func (r *Resolver) resolveDeposit(ctx context.Context, data []byte) (*Resolved, error) {
	finish := timing.FromContext(ctx).Start("indexer_decode")
	request, params, err := decodeDeposit(data)
	finish()
	if err != nil {
		return nil, err
	}
	select {
	case r.permits <- struct{}{}:
		defer func() { <-r.permits }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	finish = timing.FromContext(ctx).Start("indexer_fetch")
	defer finish()
	keys := make(map[Hash]*ring.RegistryKey)
	for i := range int(params.Count) {
		params.Keys[i], err = r.registryKey(ctx, request, keys, params.OwnerPkHashes[i].Int, params.NullifierPks[i].Int)
		if err != nil {
			return nil, err
		}
	}
	payload, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return &Resolved{Payload: payload, Resolution: &common.ProofResolution{Trees: []common.ResolvedTree{}, PublicInputHash: common.FeHex(params.PublicInputHash.Int)}}, nil
}
