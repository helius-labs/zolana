package indexed

import (
	"context"
	"encoding/json"
	"fmt"

	"zolana/prover/custom_rings/circuits/deposit"
	"zolana/prover/prover/common"
	ring "zolana/prover/prover/custom_ring"
	"zolana/prover/prover/timing"
)

func decodeDeposit(data []byte) (Request, *ring.DepositParameters, error) {
	request, err := decodeEnvelope(data)
	if err != nil {
		return request, nil, err
	}
	if request.CircuitType != common.CustomRingDepositCircuitType || len(request.Trees) != 0 || len(request.Inputs) != 0 || len(request.PublicInputs) != 1 {
		return request, nil, fmt.Errorf("invalid indexed deposit")
	}
	var base map[string]json.RawMessage
	if json.Unmarshal(request.Prepared, &base) != nil || base == nil || base["keys"] != nil {
		return request, nil, fmt.Errorf("invalid prepared deposit")
	}
	if err := validateRegistryAnchor(base, request.Registry); err != nil {
		return request, nil, err
	}
	var count uint32
	if json.Unmarshal(base["count"], &count) != nil || count < 1 || count > deposit.MaxDeposits {
		return request, nil, fmt.Errorf("invalid deposit count")
	}
	keys := make([]json.RawMessage, deposit.MaxDeposits)
	for i := range keys {
		keys[i] = json.RawMessage("null")
		if i < int(count) {
			keys[i] = registryPlaceholder()
		}
	}
	base["keys"], _ = json.Marshal(keys)
	prepared, err := json.Marshal(base)
	if err != nil {
		return request, nil, err
	}
	var params ring.DepositParameters
	if err := json.Unmarshal(prepared, &params); err != nil {
		return request, nil, err
	}
	expected, err := common.FeFromHex(request.PublicInputs[0])
	if err != nil || !params.KeyEscrow.Enabled || expected.Cmp(params.PublicInputHash) != 0 {
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
		params.Keys[i], err = r.registryKey(ctx, request, keys, params.OwnerPkHashes[i], params.NullifierPks[i])
		if err != nil {
			return nil, err
		}
	}
	payload, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return &Resolved{Payload: payload, Resolution: &common.ProofResolution{Trees: []common.ResolvedTree{}, PublicInputHash: common.FeHex(params.PublicInputHash)}}, nil
}
