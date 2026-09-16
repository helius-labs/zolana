package directspend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	direct "zolana/prover/circuits/direct_spend"
	"zolana/prover/prover/common"
)

type Request struct {
	CircuitType common.CircuitType `json:"circuitType"`
	NInputs     uint32             `json:"nInputs"`
	NOutputs    uint32             `json:"nOutputs"`
	Witness     json.RawMessage    `json:"witness"`
}

func Circuit(kind common.CircuitType, inputs, outputs uint32) (frontend.Circuit, error) {
	if !common.IsDirectSpendShape(kind, inputs, outputs) {
		return nil, fmt.Errorf("direct spend: unsupported shape %s/%d/%d", kind, inputs, outputs)
	}
	switch kind {
	case common.InputCertificateCircuitType:
		return direct.NewCertificate(int(inputs)), nil
	case common.NullifierFreshnessCircuitType:
		return direct.NewFreshness(int(inputs)), nil
	case common.SpendBalanceCircuitType:
		return direct.NewBalance(int(inputs), int(outputs)), nil
	case common.DirectPaymentCircuitType:
		return direct.NewPayment(int(inputs), int(outputs)), nil
	case common.DirectPaymentGKRCircuitType:
		payment := direct.NewPayment(int(inputs), int(outputs))
		payment.GKR = true
		return payment, nil
	}
	return nil, fmt.Errorf("direct spend: unknown circuit %s", kind)
}

func Setup(kind common.CircuitType, inputs, outputs uint32) (*common.TransferProofSystem, error) {
	circuit, err := Circuit(kind, inputs, outputs)
	if err != nil {
		return nil, err
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.TransferProofSystem{CircuitType: kind, NInputs: inputs, NOutputs: outputs,
		ConstraintSystem: ccs, ProvingKey: pk, VerifyingKey: vk}, nil
}

func Decode(data []byte) (*Request, frontend.Circuit, error) {
	var request Request
	if err := decodeJSON(data, &request); err != nil {
		return nil, nil, err
	}
	assignment, err := Circuit(request.CircuitType, request.NInputs, request.NOutputs)
	if err != nil {
		return nil, nil, err
	}
	if err := decodeJSON(request.Witness, assignment); err != nil {
		return nil, nil, err
	}
	shape, _ := Circuit(request.CircuitType, request.NInputs, request.NOutputs)
	if err := validateWitness(reflect.ValueOf(assignment).Elem(), reflect.ValueOf(shape).Elem(), "witness"); err != nil {
		return nil, nil, err
	}
	return &request, assignment, nil
}

func Prove(ps *common.TransferProofSystem, request *Request, assignment frontend.Circuit) (*common.Proof, error) {
	if ps.CircuitType != request.CircuitType || ps.NInputs != request.NInputs || ps.NOutputs != request.NOutputs {
		return nil, fmt.Errorf("direct spend: proving system does not match request")
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, err
	}
	return &common.Proof{Proof: proof}, nil
}

func ProveRequest(manager *common.LazyKeyManager, data []byte) (*common.Proof, error) {
	request, assignment, err := Decode(data)
	if err != nil {
		return nil, err
	}
	ps, err := manager.GetTransferSystem(request.CircuitType, request.NInputs, request.NOutputs)
	if err != nil {
		return nil, err
	}
	return Prove(ps, request, assignment)
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("direct spend: trailing JSON")
	}
	return nil
}

// Validate against the circuit shape without maintaining a second witness schema.
func validateWitness(value, shape reflect.Value, path string) error {
	switch shape.Kind() {
	case reflect.Struct:
		for i := 0; i < shape.NumField(); i++ {
			if shape.Type().Field(i).Tag.Get("gnark") == "-" {
				continue
			}
			if err := validateWitness(value.Field(i), shape.Field(i), path+"."+shape.Type().Field(i).Name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if value.Len() != shape.Len() {
			return fmt.Errorf("%s: expected %d elements", path, shape.Len())
		}
		for i := 0; i < shape.Len(); i++ {
			if err := validateWitness(value.Index(i), shape.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.Interface:
		text, ok := value.Interface().(string)
		if !ok || !strings.HasPrefix(text, "0x") || len(text) != 66 {
			return fmt.Errorf("%s: expected a 32-byte hexadecimal field", path)
		}
		number, ok := new(big.Int).SetString(text[2:], 16)
		if !ok || number.Sign() < 0 || number.Cmp(ecc.BN254.ScalarField()) >= 0 {
			return fmt.Errorf("%s: noncanonical field", path)
		}
		value.Set(reflect.ValueOf(number))
	default:
		return fmt.Errorf("%s: unsupported witness type", path)
	}
	return nil
}
