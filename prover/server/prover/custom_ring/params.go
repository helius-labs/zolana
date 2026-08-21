package custom_ring

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/custom_ring/auditor_key_encryption"
	"zolana/prover/prover/common"
)

const (
	scalarLen             = 32
	uncompressedPubkeyLen = 65
	TransferVariant       = "transfer"
)

type AuditorKeyEncryptionParameters struct {
	PublicInputHash *big.Int
	PrivateTxHash   *big.Int
	TxViewingSk     [scalarLen]byte
	EphSk           [scalarLen]byte
	AuditorPk       [uncompressedPubkeyLen]byte
}

type auditorKeyEncryptionParametersJSON struct {
	CircuitType     common.CircuitType `json:"circuitType"`
	Variant         string             `json:"variant"`
	PublicInputHash string             `json:"publicInputHash"`
	PrivateTxHash   string             `json:"privateTxHash"`
	TxViewingSk     string             `json:"txViewingSk"`
	EphSk           string             `json:"ephSk"`
	AuditorPk       string             `json:"auditorPk"`
}

func (p *AuditorKeyEncryptionParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(auditorKeyEncryptionParametersJSON{
		CircuitType:     common.CustomRingAuditCircuitType,
		Variant:         TransferVariant,
		PublicInputHash: common.ToHex(p.PublicInputHash),
		PrivateTxHash:   common.ToHex(p.PrivateTxHash),
		TxViewingSk:     bytesHex(p.TxViewingSk[:]),
		EphSk:           bytesHex(p.EphSk[:]),
		AuditorPk:       bytesHex(p.AuditorPk[:]),
	})
}

func (p *AuditorKeyEncryptionParameters) UnmarshalJSON(data []byte) error {
	var params auditorKeyEncryptionParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	if params.CircuitType != common.CustomRingAuditCircuitType {
		return fmt.Errorf("custom-ring-audit: invalid circuit type %q", params.CircuitType)
	}
	var err error
	if p.PublicInputHash, err = fieldFromHex(params.PublicInputHash, "publicInputHash"); err != nil {
		return err
	}
	if params.Variant != TransferVariant {
		return fmt.Errorf("custom-ring-audit: unsupported variant %q", params.Variant)
	}
	if p.PrivateTxHash, err = fieldFromHex(params.PrivateTxHash, "privateTxHash"); err != nil {
		return err
	}
	if err = bytesFromHex(p.TxViewingSk[:], params.TxViewingSk, "txViewingSk"); err != nil {
		return err
	}
	if err = bytesFromHex(p.EphSk[:], params.EphSk, "ephSk"); err != nil {
		return err
	}
	if err = validateP256Scalar(p.TxViewingSk[:], "txViewingSk"); err != nil {
		return err
	}
	if err = validateP256Scalar(p.EphSk[:], "ephSk"); err != nil {
		return err
	}
	if err = bytesFromHex(p.AuditorPk[:], params.AuditorPk, "auditorPk"); err != nil {
		return err
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), p.AuditorPk[:])
	if x == nil || y == nil {
		return fmt.Errorf("auditor-key-encryption: auditorPk is not a P256 point")
	}
	return nil
}

func (p *AuditorKeyEncryptionParameters) CreateWitness() (*auditor_key_encryption.Circuit, error) {
	if p.PublicInputHash == nil || p.PrivateTxHash == nil {
		return nil, fmt.Errorf("auditor-key-encryption: missing hash")
	}
	circuit := &auditor_key_encryption.Circuit{
		PublicInputHash: p.PublicInputHash,
		PrivateTxHash:   p.PrivateTxHash,
	}
	assignBytes(circuit.TxViewingSk[:], p.TxViewingSk[:])
	assignBytes(circuit.EphSk[:], p.EphSk[:])
	assignBytes(circuit.AuditorPk[:], p.AuditorPk[:])
	return circuit, nil
}

func assignBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = b
	}
}

func bytesHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

func bytesFromHex(dst []byte, s string, name string) error {
	if len(s) != 2+2*len(dst) || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return fmt.Errorf("auditor-key-encryption: %s is not canonical hex", name)
	}
	decoded, err := hex.DecodeString(s[2:])
	if err != nil {
		return fmt.Errorf("auditor-key-encryption: %s: %w", name, err)
	}
	if len(decoded) != len(dst) {
		return fmt.Errorf("auditor-key-encryption: %s: got %d bytes, expected %d", name, len(decoded), len(dst))
	}
	copy(dst, decoded)
	return nil
}

func validateP256Scalar(value []byte, name string) error {
	scalar := new(big.Int).SetBytes(value)
	if scalar.Sign() == 0 || scalar.Cmp(elliptic.P256().Params().N) >= 0 {
		return fmt.Errorf("auditor-key-encryption: %s is not a canonical P256 scalar", name)
	}
	return nil
}

// Canonical fields prevent silent modular reduction.
func fieldFromHex(s string, name string) (*big.Int, error) {
	if len(s) != 66 || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return nil, fmt.Errorf("auditor-key-encryption: %s is not canonical hex", name)
	}
	v := new(big.Int)
	if err := common.FromHex(v, s); err != nil {
		return nil, fmt.Errorf("auditor-key-encryption: %s: %w", name, err)
	}
	if v.Sign() < 0 || v.Cmp(ecc.BN254.ScalarField()) >= 0 {
		return nil, fmt.Errorf("auditor-key-encryption: %s is not a canonical field element", name)
	}
	return v, nil
}
