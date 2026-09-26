package server

import (
	"encoding/json"
	"errors"
	"fmt"

	"zolana/prover/prover/common"
	customring "zolana/prover/prover/custom_ring"
	mergeprover "zolana/prover/prover/merge"
	nullifiertree "zolana/prover/prover/nullifier_tree"
	"zolana/prover/prover/timing"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"
)

var (
	errCustomRingProof = errors.New("custom ring proof failed")
	errIndexedProof    = errors.New("indexed proof failed")
)

type circuitProver struct {
	keys  *common.LazyKeyManager
	trace *timing.Trace
}

func (p circuitProver) prove(payload []byte) (*common.Proof, *Error) {
	meta, err := common.ParseProofRequestMeta(payload)
	if err != nil {
		return nil, malformedBodyError(err)
	}
	return p.dispatch(meta.CircuitType, payload)
}

func (p circuitProver) dispatch(circuit common.CircuitType, payload []byte) (*common.Proof, *Error) {
	if circuit.IsRing() {
		return p.ring(circuit, payload)
	}
	switch circuit {
	case common.BatchAddressAppendCircuitType:
		return p.batchAddressAppend(payload)
	case common.TransferConfidentialCircuitType,
		common.TransferRingCircuitType,
		common.TransferRingAuthorityCircuitType:
		return p.transfer(payload)
	case common.TransferP256RingCircuitType:
		return p.p256Transfer(payload)
	case common.MergeCircuitType, common.MergeRingCircuitType:
		return p.merge(circuit, payload)
	}
	return nil, malformedBodyError(fmt.Errorf("unknown circuit type: %s", circuit))
}

func (p circuitProver) transfer(payload []byte) (*common.Proof, *Error) {
	var params transfereddsaonly.TransferParameters
	if failure := p.decode(payload, &params); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetTransferSystem(params.Variant.CircuitType(), params.NInputs, params.NOutputs)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("transfer-eddsa: %w", err))
	}
	return proved(transfereddsaonly.TransferProof{System: ps, Parameters: &params, Timing: p.trace}.Prove())
}

func (p circuitProver) p256Transfer(payload []byte) (*common.Proof, *Error) {
	var params transfereddsaonly.P256TransferParameters
	if failure := p.decode(payload, &params); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetTransferSystem(common.TransferP256RingCircuitType, params.NInputs, params.NOutputs)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("transfer-p256: %w", err))
	}
	return proved(transfereddsaonly.P256Proof{System: ps, Parameters: &params, Timing: p.trace}.Prove())
}

func (p circuitProver) merge(circuit common.CircuitType, payload []byte) (*common.Proof, *Error) {
	var params mergeprover.MergeParameters
	if failure := p.decode(payload, &params); failure != nil {
		return nil, failure
	}
	// Merge parameters carry no shape field; the declared input count is the
	// shape. Validate it before a key lookup so an unsupported count fails as a
	// bad request rather than a missing key.
	if err := params.ValidateShape(); err != nil {
		return nil, malformedBodyError(err)
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetTransferSystem(circuit, uint32(len(params.Inputs)), mergeprover.MergeNOutputs)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("%s: %w", circuit, err))
	}
	return proved(mergeprover.MergeProof{System: ps, Parameters: &params, Timing: p.trace}.Prove())
}

func (p circuitProver) ring(circuit common.CircuitType, payload []byte) (*common.Proof, *Error) {
	finishParameters := p.trace.Start("parameters")
	request, err := customring.DecodeRequest(circuit, payload)
	finishParameters()
	if err != nil {
		return nil, malformedBodyError(err)
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetRingSystem(circuit)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("%s: %w", circuit, err))
	}
	proof, err := customring.RingProof{System: ps, Parameters: request, Timing: p.trace}.Prove()
	if err != nil {
		return nil, provingError(errCustomRingProof)
	}
	return proof, nil
}

func (p circuitProver) batchAddressAppend(payload []byte) (*common.Proof, *Error) {
	var params nullifiertree.BatchAddressAppendParameters
	if failure := p.decode(payload, &params); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetBatchSystem(common.BatchAddressAppendCircuitType, params.TreeHeight, params.BatchSize)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("batch address append: %w", err))
	}
	return proved(nullifiertree.BatchAddressAppendProof{System: ps, Parameters: &params, Timing: p.trace}.Prove())
}

func (p circuitProver) decode(payload []byte, params any) *Error {
	defer p.trace.Start("parameters")()
	if err := json.Unmarshal(payload, params); err != nil {
		return malformedBodyError(err)
	}
	return nil
}

func proved(proof *common.Proof, err error) (*common.Proof, *Error) {
	if err != nil {
		return nil, provingError(err)
	}
	return proof, nil
}
