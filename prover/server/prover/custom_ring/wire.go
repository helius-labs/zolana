package custom_ring

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var errNotCanonical = errors.New("custom-ring: a value is not canonical lowercase 0x hex")

// Field is a BN254 scalar on the wire, 0x and 64 lowercase hex digits below r.
type Field struct{ *big.Int }

// Bytes is a byte string on the wire, 0x and lowercase hex. The circuit array it fills fixes its length.
type Bytes []byte

func (f Field) MarshalJSON() ([]byte, error) {
	if f.Int == nil {
		return nil, errors.New("custom-ring: missing field")
	}
	var b [32]byte
	return json.Marshal(Bytes(f.FillBytes(b[:])))
}

func (f *Field) UnmarshalJSON(data []byte) error {
	var b Bytes
	if err := b.UnmarshalJSON(data); err != nil {
		return err
	}
	if b == nil {
		return nil
	}
	value := new(big.Int).SetBytes(b)
	if len(b) != 32 || value.Cmp(fr.Modulus()) >= 0 {
		return errNotCanonical
	}
	f.Int = value
	return nil
}

func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal("0x" + hex.EncodeToString(b))
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return errNotCanonical
	}
	*b = decoded
	return nil
}
