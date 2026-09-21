package custom_ring

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/prover/common"
)

type CompressedPolicyParameters struct {
	Base            PolicyParameters
	TransactionSalt [16]byte
	HeadOldRoot     *big.Int
	HeadNewRoot     *big.Int
	HeadNext        *big.Int
	HeadIndex       *big.Int
	HeadProof       [policy.HeadMapHeight]*big.Int
}

type compressedPolicyParametersJSON struct {
	CircuitType     string          `json:"circuitType"`
	Policy          json.RawMessage `json:"policy"`
	TransactionSalt string          `json:"transactionSalt"`
	HeadOldRoot     string          `json:"headOldRoot"`
	HeadNewRoot     string          `json:"headNewRoot"`
	HeadNext        string          `json:"headNext"`
	HeadIndex       string          `json:"headIndex"`
	HeadProof       []string        `json:"headProof"`
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
		HeadOldRoot:     common.ToHex(p.HeadOldRoot),
		HeadNewRoot:     common.ToHex(p.HeadNewRoot),
		HeadNext:        common.ToHex(p.HeadNext),
		HeadIndex:       common.ToHex(p.HeadIndex),
		HeadProof:       writePath(p.HeadProof[:]),
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
	if len(raw.HeadProof) != policy.HeadMapHeight {
		return fmt.Errorf(
			"custom-ring-compressed-policy: headProof length %d is not %d",
			len(raw.HeadProof), policy.HeadMapHeight,
		)
	}
	salt, err := hex.DecodeString(strings.TrimPrefix(raw.TransactionSalt, "0x"))
	if err != nil || len(salt) != len(p.TransactionSalt) {
		return fmt.Errorf("invalid transaction salt")
	}
	copy(p.TransactionSalt[:], salt)
	if p.HeadOldRoot, err = fieldFromHex(raw.HeadOldRoot, "headOldRoot"); err != nil {
		return err
	}
	if p.HeadNewRoot, err = fieldFromHex(raw.HeadNewRoot, "headNewRoot"); err != nil {
		return err
	}
	if p.HeadNext, err = fieldFromHex(raw.HeadNext, "headNext"); err != nil {
		return err
	}
	if p.HeadIndex, err = fieldFromHex(raw.HeadIndex, "headIndex"); err != nil {
		return err
	}
	if p.Base.WindowSlots == 0 {
		return fmt.Errorf("custom-ring-compressed-policy: windowSlots is zero")
	}
	if p.HeadIndex.Sign() == 0 || p.HeadIndex.BitLen() > policy.HeadMapHeight {
		return fmt.Errorf("custom-ring-compressed-policy: headIndex must be nonzero and below 2^%d", policy.HeadMapHeight)
	}
	for i, hex := range raw.HeadProof {
		if p.HeadProof[i], err = fieldFromHex(hex, "headProof"); err != nil {
			return err
		}
	}
	return nil
}

func (p *CompressedPolicyParameters) CreateWitness() (*policy.CompressedPolicyCircuit, error) {
	base, err := p.Base.CreateWitness()
	if err != nil {
		return nil, err
	}
	circuit := &policy.CompressedPolicyCircuit{
		Policy:      *base,
		HeadOldRoot: p.HeadOldRoot,
		HeadNewRoot: p.HeadNewRoot,
		HeadNext:    p.HeadNext,
		HeadIndex:   p.HeadIndex,
	}
	for i := range circuit.TransactionSalt {
		circuit.TransactionSalt[i] = p.TransactionSalt[i]
	}
	for i := range circuit.HeadProof {
		circuit.HeadProof[i] = p.HeadProof[i]
	}
	return circuit, nil
}
