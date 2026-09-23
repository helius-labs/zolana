package custom_ring

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"zolana/prover/custom_rings/circuits/policy"
	"zolana/prover/prover/common"
)

type CompressedPolicyParameters struct {
	Base            PolicyParameters
	TransactionSalt [16]byte
}

type compressedPolicyParametersJSON struct {
	CircuitType     string          `json:"circuitType"`
	Policy          json.RawMessage `json:"policy"`
	TransactionSalt string          `json:"transactionSalt"`
}

func (p *CompressedPolicyParameters) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(&p.Base)
	if err != nil {
		return nil, err
	}
	return json.Marshal(compressedPolicyParametersJSON{
		CircuitType:     string(common.CustomRingCompressedPolicyCircuitType),
		Policy:          base,
		TransactionSalt: "0x" + hex.EncodeToString(p.TransactionSalt[:]),
	})
}

func (p *CompressedPolicyParameters) UnmarshalJSON(data []byte) error {
	var raw compressedPolicyParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.CustomRingCompressedPolicyCircuitType) {
		return fmt.Errorf("custom-ring-compressed-policy: unexpected circuitType %q", raw.CircuitType)
	}
	if err := json.Unmarshal(raw.Policy, &p.Base); err != nil {
		return err
	}
	salt, err := hex.DecodeString(strings.TrimPrefix(raw.TransactionSalt, "0x"))
	if err != nil || len(salt) != len(p.TransactionSalt) {
		return fmt.Errorf("invalid transaction salt")
	}
	copy(p.TransactionSalt[:], salt)
	if p.Base.WindowSlots == 0 {
		return fmt.Errorf("custom-ring-compressed-policy: windowSlots is zero")
	}
	return nil
}

func (p *CompressedPolicyParameters) CreateWitness() (*policy.CompressedPolicyCircuit, error) {
	base, err := p.Base.CreateWitness()
	if err != nil {
		return nil, err
	}
	circuit := &policy.CompressedPolicyCircuit{Policy: *base}
	for i := range circuit.TransactionSalt {
		circuit.TransactionSalt[i] = p.TransactionSalt[i]
	}
	return circuit, nil
}
