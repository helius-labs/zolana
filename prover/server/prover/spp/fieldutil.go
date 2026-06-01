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

// parseBigInt reads a field value with one explicit rule:
//   - a "0x" prefix means hexadecimal;
//   - a bare 64-character string is hexadecimal (the canonical field-element
//     form emitted by proofFieldHex);
//   - anything else is decimal.
//
// The fixed rule stops long decimals (e.g. a 21-digit number) from being read
// as hex by accident.
func parseBigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty field")
	}
	if rest, isHex := strings.CutPrefix(value, "0x"); isHex {
		return parseInBase(rest, 16, value)
	}
	if len(value) == 64 {
		return parseInBase(value, 16, value)
	}
	return parseInBase(value, 10, value)
}

func parseInBase(value string, base int, original string) (*big.Int, error) {
	out, ok := new(big.Int).SetString(value, base)
	if !ok {
		return nil, fmt.Errorf("invalid field %q", original)
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
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
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
		Asset:           big.NewInt(0),
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
		Asset:           utxo.Asset,
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
