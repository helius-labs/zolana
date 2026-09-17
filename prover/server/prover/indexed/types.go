package indexed

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type Request struct {
	CircuitType    common.CircuitType `json:"circuitType"`
	Prepared       json.RawMessage    `json:"prepared"`
	Trees          []Tree             `json:"trees"`
	Inputs         []Lookup           `json:"inputs"`
	PublicInputs   []string           `json:"publicInputs"`
	MinContextSlot uint64             `json:"minContextSlot,omitempty"`
}

type Tree struct {
	Address string `json:"tree"`
	ID      uint16 `json:"id"`
}

type Lookup struct {
	TreeSlot   uint8 `json:"treeSlot"`
	Commitment *Hash `json:"commitment"`
}

type Hash [32]byte

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}

func (h *Hash) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("invalid encoded hash")
	}
	decoded, err := decodeHash(value)
	if err != nil {
		return err
	}
	*h = decoded
	return nil
}

func (h Hash) String() string {
	number := new(big.Int).SetBytes(h[:])
	radix, digit := big.NewInt(58), new(big.Int)
	var encoded []byte
	for number.Sign() != 0 {
		number.QuoRem(number, radix, digit)
		encoded = append(encoded, alphabet[digit.Int64()])
	}
	for _, value := range h {
		if value != 0 {
			break
		}
		encoded = append(encoded, '1')
	}
	for left, right := 0, len(encoded)-1; left < right; left, right = left+1, right-1 {
		encoded[left], encoded[right] = encoded[right], encoded[left]
	}
	return string(encoded)
}

func decodeHash(value string) (Hash, error) {
	var result Hash
	if len(value) < 32 || len(value) > 44 {
		return result, fmt.Errorf("invalid hash length")
	}
	number, radix := new(big.Int), big.NewInt(58)
	for _, character := range value {
		digit := strings.IndexRune(alphabet, character)
		if digit < 0 {
			return result, fmt.Errorf("invalid hash encoding")
		}
		number.Mul(number, radix).Add(number, big.NewInt(int64(digit)))
	}
	if number.BitLen() > 256 {
		return result, fmt.Errorf("hash exceeds width")
	}
	number.FillBytes(result[:])
	if result.String() != value {
		return Hash{}, fmt.Errorf("noncanonical hash encoding")
	}
	return result, nil
}

func hashField(value *big.Int) (Hash, error) {
	var result Hash
	if value == nil || value.Sign() < 0 || value.Cmp(fr.Modulus()) >= 0 {
		return result, fmt.Errorf("noncanonical field")
	}
	value.FillBytes(result[:])
	return result, nil
}

func (h Hash) field() (*big.Int, error) {
	value := new(big.Int).SetBytes(h[:])
	_, err := hashField(value)
	return value, err
}

func (h Hash) hex() string {
	return common.FeHex(new(big.Int).SetBytes(h[:]))
}

type merkleContext struct {
	Tree     string `json:"tree"`
	TreeType uint16 `json:"treeType"`
}

type stateProof struct {
	Leaf          Hash          `json:"leaf"`
	MerkleContext merkleContext `json:"merkleContext"`
	Path          []Hash        `json:"path"`
	LeafIndex     uint64        `json:"leafIndex"`
	Root          Hash          `json:"root"`
	RootSeq       uint64        `json:"rootSeq"`
	RootIndex     uint16        `json:"rootIndex"`
}

type nullifierProof struct {
	Leaf             Hash          `json:"leaf"`
	MerkleContext    merkleContext `json:"merkleContext"`
	Path             []Hash        `json:"path"`
	LowElement       Hash          `json:"lowElement"`
	LowElementIndex  uint64        `json:"lowElementIndex"`
	HighElement      Hash          `json:"highElement"`
	HighElementIndex uint64        `json:"highElementIndex"`
	Root             Hash          `json:"root"`
	RootSeq          uint64        `json:"rootSeq"`
	RootIndex        uint16        `json:"rootIndex"`
}

type response[T any] struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Proofs []T `json:"proofs"`
}
