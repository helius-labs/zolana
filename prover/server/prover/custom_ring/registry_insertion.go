package custom_ring

import (
	"fmt"
	"math/big"

	"zolana/prover/custom_rings/circuits/registry"
	"zolana/prover/prover/common"
)

type registryInsertion struct {
	RegistryOldRoot *big.Int
	RegistryNewRoot *big.Int
	Member          *big.Int
	NewIndex        *big.Int
	LowMember       *big.Int
	LowNext         *big.Int
	LowKey          *big.Int
	LowIndex        *big.Int
	LowProof        [registry.Height]*big.Int
	NewProof        [registry.Height]*big.Int
}

type registryInsertionJSON struct {
	RegistryOldRoot string   `json:"registryOldRoot"`
	RegistryNewRoot string   `json:"registryNewRoot"`
	Member          string   `json:"member"`
	NewIndex        string   `json:"newIndex"`
	LowMember       string   `json:"lowMember"`
	LowNext         string   `json:"lowNext"`
	LowKey          string   `json:"lowKey"`
	LowIndex        string   `json:"lowIndex"`
	LowProof        []string `json:"lowProof"`
	NewProof        []string `json:"newProof"`
}

func (r *registryInsertion) json() registryInsertionJSON {
	return registryInsertionJSON{
		RegistryOldRoot: common.ToHex(r.RegistryOldRoot),
		RegistryNewRoot: common.ToHex(r.RegistryNewRoot),
		Member:          common.ToHex(r.Member),
		NewIndex:        common.ToHex(r.NewIndex),
		LowMember:       common.ToHex(r.LowMember),
		LowNext:         common.ToHex(r.LowNext),
		LowKey:          common.ToHex(r.LowKey),
		LowIndex:        common.ToHex(r.LowIndex),
		LowProof:        writePath(r.LowProof[:]),
		NewProof:        writePath(r.NewProof[:]),
	}
}

func (r *registryInsertion) decode(raw registryInsertionJSON, rail string) error {
	if len(raw.LowProof) != registry.Height || len(raw.NewProof) != registry.Height {
		return fmt.Errorf("%s: proof length is not %d", rail, registry.Height)
	}
	scalars := []struct {
		dst  **big.Int
		src  string
		name string
	}{
		{&r.RegistryOldRoot, raw.RegistryOldRoot, "registryOldRoot"},
		{&r.RegistryNewRoot, raw.RegistryNewRoot, "registryNewRoot"},
		{&r.Member, raw.Member, "member"},
		{&r.NewIndex, raw.NewIndex, "newIndex"},
		{&r.LowMember, raw.LowMember, "lowMember"},
		{&r.LowNext, raw.LowNext, "lowNext"},
		{&r.LowKey, raw.LowKey, "lowKey"},
		{&r.LowIndex, raw.LowIndex, "lowIndex"},
	}
	for _, s := range scalars {
		value, err := fieldFromHex(s.src, s.name)
		if err != nil {
			return err
		}
		*s.dst = value
	}
	if r.NewIndex.Sign() == 0 || r.NewIndex.BitLen() > registry.Height ||
		r.LowIndex.Cmp(r.NewIndex) >= 0 || r.LowMember.Cmp(r.Member) >= 0 || r.Member.Cmp(r.LowNext) >= 0 {
		return fmt.Errorf("%s: invalid insertion index or member range", rail)
	}
	for i := range r.LowProof {
		low, err := fieldFromHex(raw.LowProof[i], "lowProof")
		if err != nil {
			return err
		}
		r.LowProof[i] = low
		sibling, err := fieldFromHex(raw.NewProof[i], "newProof")
		if err != nil {
			return err
		}
		r.NewProof[i] = sibling
	}
	return nil
}
