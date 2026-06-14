package parse

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"zolana/prover/prover-test/poseidon"
)

func OptionalField(value string) (*big.Int, error) {
	if strings.TrimSpace(value) == "" {
		return big.NewInt(0), nil
	}
	return Field(value)
}

func Field(value string) (*big.Int, error) {
	out, err := BigInt(value)
	if err != nil {
		return nil, err
	}
	if err := validateFieldElement("field", out); err != nil {
		return nil, err
	}
	return out, nil
}

func BigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty field")
	}
	base := 10
	digits := value
	if len(value) >= 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') {
		base = 16
		digits = value[2:]
		if digits == "" {
			return nil, fmt.Errorf("empty hex field")
		}
	}
	out, ok := new(big.Int).SetString(digits, base)
	if !ok {
		return nil, fmt.Errorf("invalid field %q", value)
	}
	return out, nil
}

func Hex32(value string) ([32]byte, error) {
	bytes, err := HexBytes(value)
	if err != nil {
		return [32]byte{}, err
	}
	if len(bytes) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32 bytes, got %d", len(bytes))
	}
	var out [32]byte
	copy(out[:], bytes)
	return out, nil
}

func OptionalHex32(value string) ([32]byte, error) {
	if strings.TrimSpace(value) == "" {
		return [32]byte{}, nil
	}
	return Hex32(value)
}

func HexBytes(value string) ([]byte, error) {
	value = HexString(value)
	if value == "" {
		return nil, nil
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func HexString(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') {
		return value[2:]
	}
	return value
}

func FieldHex(value *big.Int) string {
	return fmt.Sprintf("%064x", value)
}

func BytesHex(value []byte) string {
	return hex.EncodeToString(value)
}

func FieldBytes(value *big.Int) ([32]byte, error) {
	var out [32]byte
	if err := validateFieldElement("field", value); err != nil {
		return out, err
	}
	bytes := value.Bytes()
	if len(bytes) > 32 {
		return out, fmt.Errorf("field exceeds 32 bytes")
	}
	copy(out[32-len(bytes):], bytes)
	return out, nil
}

func P256Scalar(value string) (*big.Int, error) {
	parsed, err := BigInt(value)
	if err != nil {
		return nil, err
	}
	if parsed.Sign() <= 0 || parsed.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, fmt.Errorf("scalar is outside P256 scalar field")
	}
	return parsed, nil
}

func validateFieldElement(name string, value *big.Int) error {
	return poseidon.ValidateField(name, value)
}
