package server

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/helius-labs/zolana/prover/server/prover/backend"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	nullifiertree "github.com/helius-labs/zolana/prover/server/prover/nullifier_tree"
	"github.com/helius-labs/zolana/prover/server/prover/request"
	"github.com/helius-labs/zolana/prover/server/prover/timing"
	transfereddsa "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"
)

var (
	errExtensionProof = errors.New("extension proof failed")
	errIndexedProof   = errors.New("indexed proof failed")
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
	if extension, ok := common.LookupExtension(circuit); ok {
		return p.extension(extension, payload)
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
	case common.TransferAnonymousRingEddsaCircuitType:
		return p.eddsaTransfer(payload)
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

func (p circuitProver) eddsaTransfer(payload []byte) (*common.Proof, *Error) {
	var params transfereddsa.AnonymousEddsaTransferParameters
	if failure := p.decode(payload, &params); failure != nil {
		return nil, failure
	}
	if failure := p.admission.admit(common.TransferKeyFile(common.TransferAnonymousRingEddsaCircuitType, params.NInputs, params.NOutputs)); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetTransferSystem(common.TransferAnonymousRingEddsaCircuitType, params.NInputs, params.NOutputs)
	finishKeys()
	if err != nil {
		return nil, provingError(fmt.Errorf("transfer-eddsa: %w", err))
	}
	return proved(transfereddsa.AnonymousEddsaProof{System: ps, Parameters: &params, Prover: backend.Prover(p.trace)}.Prove())
}

func (p circuitProver) extension(circuit common.ExtensionCircuit, payload []byte) (*common.Proof, *Error) {
	request := circuit.Request()
	if failure := p.decode(payload, request); failure != nil {
		return nil, extensionFailure(failure)
	}
	if failure := p.admission.admit(circuit.KeyFile); failure != nil {
		return nil, failure
	}
	finishKeys := p.trace.Start("keys")
	ps, err := p.keys.GetExtensionSystem(circuit.Type)
	finishKeys()
	if err != nil {
		return nil, extensionFailure(provingError(fmt.Errorf("%s: %w", circuit.Type, err)))
	}
	proof, err := common.ExtensionProof{System: ps, Request: request, Prover: backend.Prover(p.trace)}.Prove()
	if err != nil {
		return nil, extensionFailure(provingError(err))
	}
	return proof, nil
}

// extensionFailure is what a client reads of a failed extension request,
// on every path: errExtensionProof under the failure's own code, so the code
// still says whether the request or the proof failed. The text can carry
// private inputs, so the failure rides along only as the unexported cause,
// which the caller that reports it logs through loggedCause.
func extensionFailure(failure *Error) *Error {
	return withCause(&Error{StatusCode: failure.StatusCode, Code: failure.Code, Message: errExtensionProof.Error()}, failure)
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
