package custom_ring

import (
	"fmt"
	"math/big"

	"zolana/prover/custom_rings/circuits/registry"
	"zolana/prover/prover/common"
)

// RegistryKey opens an owner's escrowed nullifier key in the ring key registry.
type RegistryKey struct {
	Next   *big.Int
	CtHash *big.Int
	Index  uint64
	Path   [registry.Height]*big.Int
}

type registryKeyJSON struct {
	Next   string   `json:"next"`
	CtHash string   `json:"ctHash"`
	Index  uint64   `json:"index"`
	Path   []string `json:"path"`
}

// KeyEscrow is the ring's escrow mode and the registry root its keys open under.
type KeyEscrow struct {
	Enabled bool
	Root    *big.Int
}

func readKeyEscrow(enabled bool, root string) (KeyEscrow, error) {
	value, err := fieldFromHex(root, "keyRegistryRoot")
	if err != nil {
		return KeyEscrow{}, err
	}
	if !enabled && value.Sign() != 0 {
		return KeyEscrow{}, fmt.Errorf("custom-ring: keyRegistryRoot is set with keyEscrow off")
	}
	return KeyEscrow{Enabled: enabled, Root: value}, nil
}

func (e KeyEscrow) requireEscrowed(key *RegistryKey, nullifierPk *big.Int, name string) error {
	if e.Enabled && key == nil && nullifierPk.Cmp(registry.ZeroNullifierPk) != 0 {
		return fmt.Errorf("custom-ring: %s key is neither the zero key nor registered", name)
	}
	return nil
}

func writeRegistryKey(key *RegistryKey) *registryKeyJSON {
	if key == nil {
		return nil
	}
	return &registryKeyJSON{
		Next:   common.ToHex(key.Next),
		CtHash: common.ToHex(key.CtHash),
		Index:  key.Index,
		Path:   writePath(key.Path[:]),
	}
}

func readRegistryKey(src *registryKeyJSON) (*RegistryKey, error) {
	if src == nil {
		return nil, nil
	}
	if src.Index>>registry.Height != 0 {
		return nil, fmt.Errorf("custom-ring: key index exceeds %d bits", registry.Height)
	}
	key := &RegistryKey{Index: src.Index}
	var err error
	if key.Next, err = fieldFromHex(src.Next, "key next"); err != nil {
		return nil, err
	}
	if key.CtHash, err = fieldFromHex(src.CtHash, "key ctHash"); err != nil {
		return nil, err
	}
	if err = readPath(key.Path[:], src.Path, "key path"); err != nil {
		return nil, err
	}
	return key, nil
}

func assignRegistryKey(dst *registry.KeyOpening, src *RegistryKey) {
	dst.Next, dst.CtHash, dst.Index = 0, 0, 0
	for i := range dst.Path {
		dst.Path[i] = 0
	}
	if src == nil {
		return
	}
	dst.Next, dst.CtHash, dst.Index = src.Next, src.CtHash, src.Index
	for i := range dst.Path {
		dst.Path[i] = src.Path[i]
	}
}
