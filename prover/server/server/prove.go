package server

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/helius-labs/zolana/prover/server/prover/backend"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	customring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
	nullifiertree "github.com/helius-labs/zolana/prover/server/prover/nullifier_tree"
	"github.com/helius-labs/zolana/prover/server/prover/request"
	"github.com/helius-labs/zolana/prover/server/prover/timing"
	transfereddsaonly "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa_only"
)

var (
	errCustomRingProof = errors.New("custom ring proof failed")
	errIndexedProof    = errors.New("indexed proof failed")
)

type circuitProver struct {
	keys      *common.LazyKeyManager
	trace     *timing.Trace
	admission keyAdmission
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
		common.TransferRingAuthorityCircuitType,
		common.MergeCircuitType,
		common.MergeRingCircuitType:
		return p.request(payload)
	case common.TransferP256RingCircuitType:
		return p.p256Transfer(payload)
	case common.TransferEd25519RingCircuitType:
		return p.ed25519Transfer(payload)
	}
	return nil, malformedBodyError(fmt.Errorf("unknown circuit type: %s", circuit))
}

func (p circuitProver) request(payload []byte) (*common.Proof, *Error) {
	finishParameters := p.trace.Start("parameters")
	req, err := request.Parse(payload)
	finishParameters()
	if err != nil {
		return nil, malformedBodyError(err)
	}
	if failure := p.admission.admit(req.KeyFile); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetTransferSystem(req.Circuit, req.Inputs, req.Outputs)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("%s: %w", req.Circuit, err))
	}
	return proved(req.Prove(ps, backend.Prover(p.trace)))
}

func (p circuitProver) p256Transfer(payload []byte) (*common.Proof, *Error) {
	var params transfereddsaonly.P256TransferParameters
	if failure := p.decode(payload, &params); failure != nil {
		return nil, failure
	}
	if failure := p.admission.admit(common.TransferKeyFile(common.TransferP256RingCircuitType, params.NInputs, params.NOutputs)); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetTransferSystem(common.TransferP256RingCircuitType, params.NInputs, params.NOutputs)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("transfer-p256: %w", err))
	}
	return proved(transfereddsaonly.P256Proof{System: ps, Parameters: &params, Prover: backend.Prover(p.trace)}.Prove())
}

func (p circuitProver) ed25519Transfer(payload []byte) (*common.Proof, *Error) {
	var params transfereddsaonly.Ed25519TransferParameters
	if failure := p.decode(payload, &params); failure != nil {
		return nil, failure
	}
	if failure := p.admission.admit(common.TransferKeyFile(common.TransferEd25519RingCircuitType, params.NInputs, params.NOutputs)); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetTransferSystem(common.TransferEd25519RingCircuitType, params.NInputs, params.NOutputs)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("transfer-ed25519: %w", err))
	}
	return proved(transfereddsaonly.Ed25519Proof{System: ps, Parameters: &params, Prover: backend.Prover(p.trace)}.Prove())
}

func (p circuitProver) ring(circuit common.CircuitType, payload []byte) (*common.Proof, *Error) {
	finishParameters := p.trace.Start("parameters")
	request, err := customring.DecodeRequest(circuit, payload)
	finishParameters()
	if err != nil {
		return nil, customRingFailure(malformedBodyError(err))
	}
	if failure := p.admission.admit(common.RingKeyFile(circuit)); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetRingSystem(circuit)
	finishKeys()
	if err != nil {
		return nil, customRingFailure(provingError(fmt.Errorf("%s: %w", circuit, err)))
	}
	proof, err := customring.RingProof{System: ps, Parameters: request, Prover: backend.Prover(p.trace)}.Prove()
	if err != nil {
		return nil, customRingFailure(provingError(err))
	}
	return proof, nil
}

// customRingFailure is what a client reads of a failed custom-ring request,
// on every path: errCustomRingProof under the failure's own code, so the code
// still says whether the request or the proof failed. The text can carry
// private inputs, so the failure rides along only as the unexported cause,
// which the caller that reports it logs through loggedCause.
func customRingFailure(failure *Error) *Error {
	return withCause(&Error{StatusCode: failure.StatusCode, Code: failure.Code, Message: errCustomRingProof.Error()}, failure)
}

func (p circuitProver) batchAddressAppend(payload []byte) (*common.Proof, *Error) {
	var params nullifiertree.BatchAddressAppendParameters
	if failure := p.decode(payload, &params); failure != nil {
		return nil, failure
	}
	if failure := p.admission.admit(common.BatchKeyFile(common.BatchAddressAppendCircuitType, params.TreeHeight, params.BatchSize)); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetBatchSystem(common.BatchAddressAppendCircuitType, params.TreeHeight, params.BatchSize)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("batch address append: %w", err))
	}
	return proved(nullifiertree.BatchAddressAppendProof{System: ps, Parameters: &params, Prover: backend.Prover(p.trace)}.Prove())
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
