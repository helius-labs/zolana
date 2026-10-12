// Package request decodes and proves /prove bodies for the transfer and merge
// circuits.
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
	ErrMalformed   = errors.New("malformed proof request")
	ErrUnsupported = errors.New("unsupported proof request")
	ErrSystem      = errors.New("proving system does not match the request")
)

type parameters interface {
	ValidateShape() error
	CreateWitness() (frontend.Circuit, error)
}

// Request is a decoded /prove body and the proving key it needs.
type Request struct {
	Circuit common.CircuitType
	Inputs  uint32
	Outputs uint32
	// KeyFile is empty when no key exists for the shape.
	KeyFile string
	params  parameters
}

// Parse decodes body leniently: unknown fields are ignored and absent values
// decode as zero. Values must be canonical field elements.
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
		// The input count is the merge's shape and selects its key.
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

// canonical reports whether every big.Int in value is below the BN254 scalar
// field modulus; gnark would otherwise reduce it silently.
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

// Prover runs Groth16 on the assignment assign builds.
type Prover func(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, assign func() (frontend.Circuit, error)) (groth16.Proof, error)

// Prove proves r with system and reports the system's proving-key digest on
// the proof. A nil prove runs gnark's CPU prover.
func (r *Request) Prove(system *common.TransferProofSystem, prove Prover) (*common.Proof, error) {
	if system == nil {
		return nil, ErrSystem
	}
	if system.CircuitType != r.Circuit || system.NInputs != r.Inputs || system.NOutputs != r.Outputs {
		return nil, fmt.Errorf("%w: %s %dx%d system for a %s %dx%d request", ErrSystem,
			system.CircuitType, system.NInputs, system.NOutputs, r.Circuit, r.Inputs, r.Outputs)
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

// Verify checks proof against r's public inputs.
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
