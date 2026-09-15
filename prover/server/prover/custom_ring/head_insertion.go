package custom_ring

import (
	"fmt"
	"math/big"

	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/prover/common"
)

type headInsertion struct {
	HeadOldRoot  *big.Int
	HeadNewRoot  *big.Int
	Member       *big.Int
	NewIndex     *big.Int
	LowMember    *big.Int
	LowNext      *big.Int
	LowNullifier *big.Int
	LowIndex     *big.Int
	LowProof     [policy.HeadMapHeight]*big.Int
	NewProof     [policy.HeadMapHeight]*big.Int
}

type headInsertionJSON struct {
	HeadOldRoot  string   `json:"headOldRoot"`
	HeadNewRoot  string   `json:"headNewRoot"`
	Member       string   `json:"member"`
	NewIndex     string   `json:"newIndex"`
	LowMember    string   `json:"lowMember"`
	LowNext      string   `json:"lowNext"`
	LowNullifier string   `json:"lowNullifier"`
	LowIndex     string   `json:"lowIndex"`
	LowProof     []string `json:"lowProof"`
	NewProof     []string `json:"newProof"`
}

func (h *headInsertion) json() headInsertionJSON {
	return headInsertionJSON{
		HeadOldRoot:  common.ToHex(h.HeadOldRoot),
		HeadNewRoot:  common.ToHex(h.HeadNewRoot),
		Member:       common.ToHex(h.Member),
		NewIndex:     common.ToHex(h.NewIndex),
		LowMember:    common.ToHex(h.LowMember),
		LowNext:      common.ToHex(h.LowNext),
		LowNullifier: common.ToHex(h.LowNullifier),
		LowIndex:     common.ToHex(h.LowIndex),
		LowProof:     writePath(h.LowProof[:]),
		NewProof:     writePath(h.NewProof[:]),
	}
}

func (h *headInsertion) decode(raw headInsertionJSON, rail string) error {
	if len(raw.LowProof) != policy.HeadMapHeight || len(raw.NewProof) != policy.HeadMapHeight {
		return fmt.Errorf("%s: proof length is not %d", rail, policy.HeadMapHeight)
	}
	scalars := []struct {
		dst  **big.Int
		src  string
		name string
	}{
		{&h.HeadOldRoot, raw.HeadOldRoot, "headOldRoot"},
		{&h.HeadNewRoot, raw.HeadNewRoot, "headNewRoot"},
		{&h.Member, raw.Member, "member"},
		{&h.NewIndex, raw.NewIndex, "newIndex"},
		{&h.LowMember, raw.LowMember, "lowMember"},
		{&h.LowNext, raw.LowNext, "lowNext"},
		{&h.LowNullifier, raw.LowNullifier, "lowNullifier"},
		{&h.LowIndex, raw.LowIndex, "lowIndex"},
	}
	for _, s := range scalars {
		value, err := fieldFromHex(s.src, s.name)
		if err != nil {
			return err
		}
		*s.dst = value
	}
	if h.NewIndex.Sign() == 0 || h.NewIndex.BitLen() > policy.HeadMapHeight ||
		h.LowIndex.Cmp(h.NewIndex) >= 0 || h.LowMember.Cmp(h.Member) >= 0 || h.Member.Cmp(h.LowNext) >= 0 {
		return fmt.Errorf("%s: invalid insertion index or member range", rail)
	}
	for i := range h.LowProof {
		low, err := fieldFromHex(raw.LowProof[i], "lowProof")
		if err != nil {
			return err
		}
		h.LowProof[i] = low
		sibling, err := fieldFromHex(raw.NewProof[i], "newProof")
		if err != nil {
			return err
		}
		h.NewProof[i] = sibling
	}
	return nil
}
