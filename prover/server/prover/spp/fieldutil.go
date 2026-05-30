package spp

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark/frontend"
)

func optionalU64(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func optionalField(value string) (*big.Int, error) {
	if value == "" {
		return big.NewInt(0), nil
	}
	return parseField(value)
}

func parseField(value string) (*big.Int, error) {
	out, err := parseBigInt(value)
	if err != nil {
		return nil, err
	}
	if err := validateFieldElement("field", out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseBigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
	if value == "" {
		return nil, fmt.Errorf("empty field")
	}
	base := 10
	if len(value) > 20 || strings.IndexFunc(value, func(r rune) bool {
		return (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
	}) >= 0 {
		base = 16
	}
	out, ok := new(big.Int).SetString(value, base)
	if !ok {
		return nil, fmt.Errorf("invalid field %q", value)
	}
	return out, nil
}

func parseHex32(value string) ([32]byte, error) {
	bytes, err := parseHexBytes(value)
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

func parseOptionalHex32(value string) ([32]byte, error) {
	if strings.TrimSpace(value) == "" {
		return [32]byte{}, nil
	}
	return parseHex32(value)
}

func parseHexBytes(value string) ([]byte, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	if value == "" {
		return nil, nil
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func proofZeroUtxo() Utxo {
	return Utxo{
		Domain:          big.NewInt(0),
		Owner:           big.NewInt(0),
		AssetID:         big.NewInt(0),
		AssetAmount:     big.NewInt(0),
		Blinding:        big.NewInt(0),
		DataHash:        big.NewInt(0),
		PolicyData:      big.NewInt(0),
		PolicyProgramID: big.NewInt(0),
	}
}

func toProofCircuitFields(utxo Utxo) UtxoCircuitFields {
	return UtxoCircuitFields{
		Domain:          utxo.Domain,
		Owner:           utxo.Owner,
		AssetID:         utxo.AssetID,
		AssetAmount:     utxo.AssetAmount,
		Blinding:        utxo.Blinding,
		DataHash:        utxo.DataHash,
		PolicyData:      utxo.PolicyData,
		PolicyProgramID: utxo.PolicyProgramID,
	}
}

func proofZeroVariableSlice(n int) []frontend.Variable {
	out := make([]frontend.Variable, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}

func fillProofPath(path []frontend.Variable, dirs []frontend.Variable, siblings []*big.Int, directions []int) {
	for i := range siblings {
		path[i] = siblings[i]
		dirs[i] = big.NewInt(int64(directions[i]))
	}
}

func proofBigIntsToVariables(values []*big.Int) []frontend.Variable {
	out := make([]frontend.Variable, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func proofVariablesToBigInts(values []frontend.Variable) ([]*big.Int, error) {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		switch v := value.(type) {
		case *big.Int:
			out[i] = new(big.Int).Set(v)
		case int:
			out[i] = big.NewInt(int64(v))
		case int64:
			out[i] = big.NewInt(v)
		default:
			return nil, fmt.Errorf("spp: unexpected witness variable type %T", value)
		}
	}
	return out, nil
}

func proofTrimTrailingZeroHexes(values []*big.Int) []string {
	end := len(values)
	for end > 0 && values[end-1].Sign() == 0 {
		end--
	}
	out := make([]string, end)
	for i := 0; i < end; i++ {
		out[i] = proofFieldHex(values[i])
	}
	return out
}

func proofBigIntHexes(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = proofFieldHex(value)
	}
	return out
}

func proofFieldHex(value *big.Int) string {
	return fmt.Sprintf("%064x", value)
}

func proofBytesHex(value []byte) string {
	return fmt.Sprintf("%x", value)
}

func proofFieldBytes(value *big.Int) [32]byte {
	var out [32]byte
	if value == nil {
		return out
	}
	bytes := value.Bytes()
	copy(out[32-len(bytes):], bytes)
	return out
}
