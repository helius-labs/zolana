package custom_ring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Request fields carry the circuit field names, their tags the wire names.

type AuditParams struct {
	PrivateTxHash Field `json:"privateTxHash"`
	TxViewingSk   Bytes `json:"txViewingSk"`
	EphSk         Bytes `json:"ephSk"`
	AuditorPk     Bytes `json:"auditorPk"`
	Salt          Bytes `json:"salt"`
}

type AuditOpening struct {
	Domain        Field `json:"domain"`
	TreeID        Field `json:"treeId"`
	OwnerHash     Field `json:"ownerHash"`
	Asset         Field `json:"asset"`
	Amount        Field `json:"amount"`
	Blinding      Field `json:"blinding"`
	DataHash      Field `json:"dataHash"`
	RingDataHash  Field `json:"ringDataHash"`
	RingProgramID Field `json:"ringProgramId"`
}

type BaseParams struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash Field  `json:"publicInputHash"`
	AuditParams
	NOut    uint8          `json:"nOut"`
	Outputs []AuditOpening `json:"outputs"`
}

type Opening struct {
	Domain        Field `json:"domain"`
	TreeID        Field `json:"treeId"`
	OwnerPkHash   Field `json:"ownerPkHash"`
	NullifierPk   Field `json:"nullifierPk"`
	Asset         Field `json:"asset"`
	Amount        Field `json:"amount"`
	Blinding      Field `json:"blinding"`
	DataHash      Field `json:"dataHash"`
	RingDataHash  Field `json:"ringDataHash"`
	RingProgramID Field `json:"ringProgramId"`
}

// A nil key assigns zeros, the circuit only skips it for an unescrowed output.
type OutputOpening struct {
	Opening
	Key *RegistryKey `json:"key,omitempty"`
}

type RegistryKey struct {
	Next   Field   `json:"next"`
	CtHash Field   `json:"ctHash"`
	Index  uint64  `json:"index"`
	Path   []Field `json:"path"`
}

type Source struct {
	ListId    uint8 `json:"listId"`
	OwnerHash Field `json:"ownerHash"`
}

type OutflowLimit struct {
	Asset       Field `json:"asset"`
	Cap         Field `json:"cap"`
	CosignAbove Field `json:"cosignAbove"`
}

type ListFact struct {
	Enabled                  bool    `json:"enabled"`
	TreeSlot                 uint8   `json:"treeSlot"`
	Mode                     uint8   `json:"mode"`
	ListId                   uint8   `json:"listId"`
	State                    uint8   `json:"state"`
	AbsentBranch             uint8   `json:"absentBranch"`
	Member                   Field   `json:"member"`
	ContentHash              Field   `json:"contentHash"`
	Version                  uint64  `json:"version"`
	Blinding                 Field   `json:"blinding"`
	NullifierLowValue        Field   `json:"low"`
	NullifierNextValue       Field   `json:"next"`
	NullifierLowPathElements []Field `json:"nfPathElements"`
	NullifierLowPathIndex    uint64  `json:"nfPathIndex"`
	StatePathElements        []Field `json:"statePathElements"`
	StatePathIndex           uint64  `json:"statePathIndex"`
}

type PolicyParams struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash Field  `json:"publicInputHash"`
	AuditParams
	NIn                uint8           `json:"nIn"`
	NOut               uint8           `json:"nOut"`
	Inputs             []Opening       `json:"inputs"`
	Outputs            []OutputOpening `json:"outputs"`
	AddressChain       Field           `json:"addressChain"`
	PrivateTxBlinding  Field           `json:"privateTxBlinding"`
	Sources            []Source        `json:"sources"`
	PolicyLen          uint8           `json:"policyLen"`
	Rules              []Field         `json:"ruleEnc"`
	InlineAssets       []Field         `json:"inlineAssets"`
	InlineLimits       []Field         `json:"inlineLimits"`
	InlineCount        uint8           `json:"inlineCount"`
	Limits             []OutflowLimit  `json:"limits"`
	LimitCount         uint8           `json:"limitCount"`
	TreeSlots          TreeSlots       `json:"treeSlots"`
	AddressTreeID      Field           `json:"addressTreeId"`
	RingID             Field           `json:"ringId"`
	NamespaceOwnerHash Field           `json:"namespaceOwnerHash"`
	ApprovalRequired   bool            `json:"approvalRequired"`
	KeyEscrow          bool            `json:"keyEscrow"`
	KeyRegistryRoot    Field           `json:"keyRegistryRoot"`
	ListFacts          []ListFact      `json:"answers"`
}

type DelegatePolicyParams struct {
	CircuitType string       `json:"circuitType"`
	Policy      PolicyParams `json:"policy"`
}

type KeyRegisterParams struct {
	CircuitType     string  `json:"circuitType"`
	PublicInputHash Field   `json:"publicInputHash"`
	RegistryOldRoot Field   `json:"registryOldRoot"`
	RegistryNewRoot Field   `json:"registryNewRoot"`
	Member          Field   `json:"member"`
	NewIndex        Field   `json:"newIndex"`
	LowMember       Field   `json:"lowMember"`
	LowNext         Field   `json:"lowNext"`
	LowKey          Field   `json:"lowKey"`
	LowIndex        Field   `json:"lowIndex"`
	LowProof        []Field `json:"lowProof"`
	NewProof        []Field `json:"newProof"`
	NullifierSecret Bytes   `json:"nullifierSecret"`
	EphSk           Bytes   `json:"ephSk"`
	AuditorPk       Bytes   `json:"auditorPk"`
}

type DepositParams struct {
	CircuitType     string         `json:"circuitType"`
	PublicInputHash Field          `json:"publicInputHash"`
	ContextHash     Field          `json:"contextHash"`
	Count           uint32         `json:"count"`
	OwnerPkHashes   []Field        `json:"ownerPkHashes"`
	NullifierPks    []Field        `json:"nullifierPks"`
	Blindings       []Field        `json:"blindings"`
	Keys            []*RegistryKey `json:"keys"`
	EphSk           Bytes          `json:"ephSk"`
	AuditorPk       Bytes          `json:"auditorPk"`
	KeyEscrow       bool           `json:"keyEscrow"`
	KeyRegistryRoot Field          `json:"keyRegistryRoot"`
}

// TreeSlots pads the populated prefix on the wire with zero slots.
type TreeSlots []common.TreeSlotParams

type treeSlot struct {
	ID            Field `json:"id"`
	UtxoRoot      Field `json:"utxoRoot"`
	NullifierRoot Field `json:"nullifierRoot"`
}

func (s TreeSlots) MarshalJSON() ([]byte, error) {
	out := []treeSlot{}
	for _, slot := range s {
		if slot.UtxoRoot != nil && slot.UtxoRoot.Sign() == 0 {
			break
		}
		out = append(out, treeSlot{Field{slot.ID}, Field{slot.UtxoRoot}, Field{slot.NullifierRoot}})
	}
	return json.Marshal(out)
}

func (s *TreeSlots) UnmarshalJSON(data []byte) error {
	var slots []treeSlot
	if err := Unmarshal(data, &slots); err != nil {
		return err
	}
	if len(slots) == 0 || len(slots) > shared.InputTrees {
		return fmt.Errorf("custom-ring: %d tree slots, expected 1..%d", len(slots), shared.InputTrees)
	}
	*s = make(TreeSlots, shared.InputTrees)
	for i := range *s {
		(*s)[i] = common.TreeSlotParams{ID: new(big.Int), UtxoRoot: new(big.Int), NullifierRoot: new(big.Int)}
		if i < len(slots) {
			(*s)[i] = common.TreeSlotParams{ID: slots[i].ID.Int, UtxoRoot: slots[i].UtxoRoot.Int, NullifierRoot: slots[i].NullifierRoot.Int}
		}
	}
	return nil
}

// Unmarshal rejects unknown fields and trailing data.
func Unmarshal(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("custom-ring: trailing data after the request")
	}
	return nil
}
