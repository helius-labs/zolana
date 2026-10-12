// Package request decodes and proves the body of a /prove request for the
// transfer and merge circuits. The prover server and the local provers built
// on this module (the browser and mobile SDKs) all prove through it, so a body
// one of them accepts proves the same statement on the others.
package request

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	merge "github.com/helius-labs/zolana/prover/server/prover/merge"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa_only"
)

var (
	// ErrMalformed wraps every failure to decode or validate a body.
	ErrMalformed = errors.New("malformed proof request")
	// ErrUnsupported is a circuit or shape this package does not prove.
	ErrUnsupported = errors.New("unsupported proof request")
	// ErrSystem is a proving system loaded for another circuit or shape.
	ErrSystem = errors.New("proving system does not match the request")
)

type parameters interface {
	ValidateShape() error
	CreateWitness() (frontend.Circuit, error)
}

// Request is a decoded /prove body and the proving key it names.
type Request struct {
	Circuit common.CircuitType
	Inputs  uint32
	Outputs uint32
	// KeyFile is the proving key file the body needs, as proving-keys.lock
	// names it, or empty when the shape has none.
	KeyFile string
	params  parameters
}

// Parse decodes body for the transfer and merge circuits and names its key.
// It accepts what the prover server has always accepted: unknown fields are
// ignored, an absent value decodes as zero, and a transfer's shape is checked
// when it is proved. Every value must be a canonical BN254 field element.
// Local provers, which are built for one SDK release, use ParseStrict.
func Parse(body []byte) (*Request, error) {
	var envelope struct {
		CircuitType common.CircuitType `json:"circuitType"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	request := &Request{Circuit: envelope.CircuitType}
	switch envelope.CircuitType {
	case common.TransferConfidentialCircuitType, common.TransferRingCircuitType, common.TransferRingAuthorityCircuitType:
		params := new(transfer.TransferParameters)
		if err := json.Unmarshal(body, params); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		request.Inputs, request.Outputs, request.params = params.NInputs, params.NOutputs, params
	case common.MergeCircuitType, common.MergeRingCircuitType:
		params := new(merge.MergeParameters)
		if err := json.Unmarshal(body, params); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		// A merge carries no shape field: the input count is its shape, so it
		// is checked before the key is named from it.
		if err := params.ValidateShape(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		request.Inputs, request.Outputs, request.params = uint32(len(params.Inputs)), merge.MergeNOutputs, params
	default:
		return nil, fmt.Errorf("%w: circuit type %q", ErrUnsupported, envelope.CircuitType)
	}
	if !canonical(reflect.ValueOf(request.params)) {
		return nil, fmt.Errorf("%w: a value is not a canonical field element", ErrMalformed)
	}
	request.KeyFile = common.TransferKeyFile(request.Circuit, request.Inputs, request.Outputs)
	return request, nil
}

// canonical reports whether every big.Int reachable from value is in
// [0, BN254 scalar field modulus). gnark reduces larger values silently,
// which would prove a statement other than the one the body spells out.
func canonical(value reflect.Value) bool {
	if value.Type() == reflect.TypeOf((*big.Int)(nil)) {
		if value.IsNil() {
			return true
		}
		number := value.Interface().(*big.Int)
		return number.Sign() >= 0 && number.Cmp(ecc.BN254.ScalarField()) < 0
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		return value.IsNil() || canonical(value.Elem())
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if value.Type().Field(index).IsExported() && !canonical(value.Field(index)) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if !canonical(value.Index(index)) {
				return false
			}
		}
	}
	return true
}

// Prover runs Groth16 on the assignment assign builds. The prover server
// passes its backend, which can prove on a GPU; a local prover passes its own.
type Prover func(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, assign func() (frontend.Circuit, error)) (groth16.Proof, error)

// Prove proves r with system, which must be the system r.KeyFile names, and
// reports the system's proving-key digest on the proof. A nil prove runs
// gnark's CPU prover; the server passes its backend.
func (r *Request) Prove(system *common.TransferProofSystem, prove Prover) (*common.Proof, error) {
	if system == nil || system.CircuitType != r.Circuit || system.NInputs != r.Inputs || system.NOutputs != r.Outputs {
		return nil, ErrSystem
	}
	if prove == nil {
		prove = cpuProve
	}
	proof, err := prove(system.ConstraintSystem, system.ProvingKey, r.assignment)
	if err != nil {
		return nil, err
	}
	return &common.Proof{Proof: proof, ProvingKeySha256: system.ProvingKeySha256}, nil
}

// Verify checks proof against r's public inputs with system's verifying key.
func (r *Request) Verify(system *common.TransferProofSystem, proof *common.Proof) error {
	if system == nil || proof == nil || proof.Proof == nil {
		return ErrSystem
	}
	assignment, err := r.assignment()
	if err != nil {
		return err
	}
	public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return groth16.Verify(proof.Proof, system.VerifyingKey, public)
}

func cpuProve(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, assign func() (frontend.Circuit, error)) (groth16.Proof, error) {
	assignment, err := assign()
	if err != nil {
		return nil, err
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	return groth16.Prove(ccs, pk, full)
}

func (r *Request) assignment() (frontend.Circuit, error) {
	if err := r.params.ValidateShape(); err != nil {
		return nil, err
	}
	assignment, err := r.params.CreateWitness()
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	return assignment, nil
}
