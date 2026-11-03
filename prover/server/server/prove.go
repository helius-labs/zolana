package server

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

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
	request, failure := p.admit(circuit, payload)
	if failure != nil {
		return nil, failure
	}
	return request.prove()
}

// admittedRequest is a body decoded into its circuit's parameters and admitted
// to the proving key its shape names, before any key is loaded.
type admittedRequest struct {
	// keyFile is the proving key the decoded shape names, empty when the
	// shape has none.
	keyFile string
	// params is the decoded request. Encoding it drops whatever the circuit
	// does not read, so two bodies that prove the same thing encode alike.
	params any
	// witness builds the circuit assignment, without proving it.
	witness func() (frontend.Circuit, error)
	// redact maps a failure to what a client may read of it.
	redact func(*Error) *Error
	prove  func() (*common.Proof, *Error)
}

func (p circuitProver) admit(circuit common.CircuitType, payload []byte) (*admittedRequest, *Error) {
	if extension, ok := common.LookupExtension(circuit); ok {
		return p.extension(extension, payload)
	}
	switch circuit {
	case common.BatchAddressAppendCircuitType:
		return p.batchAddressAppend(payload)
	case common.TransferConfidentialCircuitType,
		common.TransferRingCircuitType,
		common.TransferRingAuthorityCircuitType,
		common.TransferConfidentialEddsaCircuitType,
		common.MergeCircuitType,
		common.MergeRingCircuitType:
		return p.request(payload)
	case common.TransferAnonymousRingEddsaCircuitType:
		return p.eddsaTransfer(payload)
	}
	return nil, malformedBodyError(fmt.Errorf("unknown circuit type: %s", circuit))
}

// validateQueued admits a body for the queue and returns the encoding the
// queue dedupes it by. A queued body is checked only once a worker dequeues
// it, so this is the last point a malformed body can be refused before it
// costs Redis state: the body must name a key this deployment serves, match
// that key's shape, and fill every value of the circuit's witness.
func (p circuitProver) validateQueued(circuit common.CircuitType, payload []byte) ([]byte, *Error) {
	request, failure := p.admit(circuit, payload)
	if failure != nil {
		return nil, failure
	}
	if request.keyFile == "" {
		return nil, request.redact(malformedBodyError(fmt.Errorf("no %s proving key for the request's shape", circuit)))
	}
	if err := completeWitness(request.witness); err != nil {
		return nil, request.redact(malformedBodyError(err))
	}
	canonical, err := canonicalBody(circuit, request.params)
	if err != nil {
		return nil, request.redact(malformedBodyError(err))
	}
	return canonical, nil
}

// canonicalBody encodes params as the body a worker reads. A worker routes a
// body by its circuitType, which an extension's parameters do not carry, so it
// is kept beside them.
func canonicalBody(circuit common.CircuitType, params any) ([]byte, error) {
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	if _, ok := fields["circuitType"]; ok {
		return encoded, nil
	}
	circuitType, err := json.Marshal(circuit)
	if err != nil {
		return nil, err
	}
	fields["circuitType"] = circuitType
	return json.Marshal(fields)
}

// completeWitness builds the full witness the prover would solve, which fails
// on any value the body left out. A malformed assignment can panic inside
// gnark, and that is a refusal too, not a crash.
func completeWitness(build func() (frontend.Circuit, error)) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("incomplete witness: %v", recovered)
		}
	}()
	assignment, err := build()
	if err != nil {
		return err
	}
	_, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	return err
}

func asIs(failure *Error) *Error { return failure }

func (p circuitProver) request(payload []byte) (*admittedRequest, *Error) {
	finishParameters := p.trace.Start("parameters")
	req, err := request.Parse(payload)
	finishParameters()
	if err != nil {
		return nil, malformedBodyError(err)
	}
	if failure := p.admission.admit(req.KeyFile); failure != nil {
		return nil, failure
	}
	return &admittedRequest{
		keyFile: req.KeyFile,
		params:  req,
		witness: req.Witness,
		redact:  asIs,
		prove: func() (*common.Proof, *Error) {
			finishKeys := p.trace.Start("keys")
			ps, err := p.keys.GetTransferSystem(req.Circuit, req.Inputs, req.Outputs)
			finishKeys()
			if err != nil {
				return nil, provingError(fmt.Errorf("%s: %w", req.Circuit, err))
			}
			return proved(req.Prove(ps, backend.Prover(p.trace)))
		},
	}, nil
}

func (p circuitProver) eddsaTransfer(payload []byte) (*admittedRequest, *Error) {
	params := new(transfereddsa.AnonymousEddsaTransferParameters)
	if failure := p.decode(payload, params); failure != nil {
		return nil, failure
	}
	keyFile := common.TransferKeyFile(common.TransferAnonymousRingEddsaCircuitType, params.NInputs, params.NOutputs)
	if failure := p.admission.admit(keyFile); failure != nil {
		return nil, failure
	}
	return &admittedRequest{
		keyFile: keyFile,
		params:  params,
		witness: func() (frontend.Circuit, error) {
			if err := params.ValidateShape(); err != nil {
				return nil, err
			}
			return params.CreateWitness()
		},
		redact: asIs,
		prove: func() (*common.Proof, *Error) {
			finishKeys := p.trace.Start("keys")
			ps, err := p.keys.GetTransferSystem(common.TransferAnonymousRingEddsaCircuitType, params.NInputs, params.NOutputs)
			finishKeys()
			if err != nil {
				return nil, provingError(fmt.Errorf("transfer-eddsa: %w", err))
			}
			return proved(transfereddsa.AnonymousEddsaProof{System: ps, Parameters: params, Prover: backend.Prover(p.trace)}.Prove())
		},
	}, nil
}

func (p circuitProver) extension(circuit common.ExtensionCircuit, payload []byte) (*admittedRequest, *Error) {
	request := circuit.Request()
	if failure := p.decode(payload, request); failure != nil {
		return nil, extensionFailure(failure)
	}
	if failure := p.admission.admit(circuit.KeyFile); failure != nil {
		return nil, failure
	}
	return &admittedRequest{
		keyFile: circuit.KeyFile,
		params:  request,
		witness: request.Assignment,
		redact:  extensionFailure,
		prove: func() (*common.Proof, *Error) {
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
		},
	}, nil
}

// extensionFailure is what a client reads of a failed extension request,
// on every path: errExtensionProof under the failure's own code, so the code
// still says whether the request or the proof failed. The text can carry
// private inputs, so the failure rides along only as the unexported cause,
// which the caller that reports it logs through loggedCause.
func extensionFailure(failure *Error) *Error {
	return withCause(&Error{StatusCode: failure.StatusCode, Code: failure.Code, Message: errExtensionProof.Error()}, failure)
}

func (p circuitProver) batchAddressAppend(payload []byte) (*admittedRequest, *Error) {
	params := new(nullifiertree.BatchAddressAppendParameters)
	if failure := p.decode(payload, params); failure != nil {
		return nil, failure
	}
	keyFile := common.BatchKeyFile(common.BatchAddressAppendCircuitType, params.TreeHeight, params.BatchSize)
	if failure := p.admission.admit(keyFile); failure != nil {
		return nil, failure
	}
	return &admittedRequest{
		keyFile: keyFile,
		params:  params,
		witness: func() (frontend.Circuit, error) {
			if err := params.ValidateShape(); err != nil {
				return nil, err
			}
			return params.CreateWitness()
		},
		redact: asIs,
		prove: func() (*common.Proof, *Error) {
			finishKeys := p.trace.Start("keys")
			ps, err := p.keys.GetBatchSystem(common.BatchAddressAppendCircuitType, params.TreeHeight, params.BatchSize)
			finishKeys()
			if err != nil {
				return nil, provingError(fmt.Errorf("batch address append: %w", err))
			}
			return proved(nullifiertree.BatchAddressAppendProof{System: ps, Parameters: params, Prover: backend.Prover(p.trace)}.Prove())
		},
	}, nil
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
