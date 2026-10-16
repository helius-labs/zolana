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

// CtHash is the hash of the owner's escrowed key ciphertext, zero without escrow.
type OutputOpening struct {
	Opening
	CtHash Field `json:"ctHash"`
}

// RecordOpening opens a member's record in a member registry.
type RecordOpening struct {
	Next      Field   `json:"next"`
	Lists     uint64  `json:"lists"`
	EscrowKey Field   `json:"escrowKey"`
	Index     uint64  `json:"index"`
	Path      []Field `json:"path"`
}

// MemberOpening proves a member present, or absent under the low record. A nil
// opening assigns zeros, the circuit only skips it for a slot that is no live UTXO.
type MemberOpening struct {
	Present bool `json:"present"`
	RecordOpening
	LowMember Field  `json:"lowMember"`
	LowNext   Field  `json:"lowNext"`
	LowLists  uint64 `json:"lowLists"`
	LowEscrow Field  `json:"lowEscrow"`
}

// Registry is zero for a list the ring's own registry serves, else the curator registry address.
type Source struct {
	ListId   uint8 `json:"listId"`
	Registry Field `json:"registry"`
}

type OutflowLimit struct {
	Asset       Field `json:"asset"`
	Cap         Field `json:"cap"`
	CosignAbove Field `json:"cosignAbove"`
}

type PolicyParams struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash Field  `json:"publicInputHash"`
	AuditParams
	NIn                uint8            `json:"nIn"`
	NOut               uint8            `json:"nOut"`
	Inputs             []Opening        `json:"inputs"`
	Outputs            []OutputOpening  `json:"outputs"`
	AddressChain       Field            `json:"addressChain"`
	PrivateTxBlinding  Field            `json:"privateTxBlinding"`
	Sources            []Source         `json:"sources"`
	PolicyLen          uint8            `json:"policyLen"`
	Rules              []Field          `json:"ruleEnc"`
	InlineAssets       []Field          `json:"inlineAssets"`
	InlineLimits       []Field          `json:"inlineLimits"`
	InlineCount        uint8            `json:"inlineCount"`
	Limits             []OutflowLimit   `json:"limits"`
	LimitCount         uint8            `json:"limitCount"`
	TreeSlots          TreeSlots        `json:"treeSlots"`
	AddressTreeID      Field            `json:"addressTreeId"`
	RingID             Field            `json:"ringId"`
	NamespaceOwnerHash Field            `json:"namespaceOwnerHash"`
	ApprovalRequired   bool             `json:"approvalRequired"`
	KeyEscrow          bool             `json:"keyEscrow"`
	MemberRegistryRoot Field            `json:"memberRegistryRoot"`
	Subjects           []*MemberOpening `json:"subjects"`
	ForeignRoot        Field            `json:"foreignRoot"`
	ForeignSubjects    []*MemberOpening `json:"foreignSubjects"`
}

type DelegatePolicyParams struct {
	CircuitType string       `json:"circuitType"`
	Policy      PolicyParams `json:"policy"`
}

// RecordUpdate rewrites one record, or inserts it after the low record when exists is off.
type RecordUpdate struct {
	Exists    bool    `json:"exists"`
	Next      Field   `json:"next"`
	Index     uint64  `json:"index"`
	Path      []Field `json:"path"`
	LowMember Field   `json:"lowMember"`
	LowNext   Field   `json:"lowNext"`
	LowLists  uint64  `json:"lowLists"`
	LowEscrow Field   `json:"lowEscrow"`
	LowIndex  uint64  `json:"lowIndex"`
	LowPath   []Field `json:"lowPath"`
}

type KeyRegisterParams struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash Field  `json:"publicInputHash"`
	RegistryOldRoot Field  `json:"registryOldRoot"`
	RegistryNewRoot Field  `json:"registryNewRoot"`
	Member          Field  `json:"member"`
	Lists           uint64 `json:"lists"`
	RecordUpdate
	NullifierSecret Bytes `json:"nullifierSecret"`
	EphSk           Bytes `json:"ephSk"`
	AuditorPk       Bytes `json:"auditorPk"`
}

// MemberUpdate is one batch item as the program authorizes it. A nil item is padding.
type MemberUpdate struct {
	Member       Field  `json:"member"`
	OldLists     uint64 `json:"oldLists"`
	OldEscrowKey Field  `json:"oldEscrowKey"`
	Lists        uint64 `json:"lists"`
	EscrowKey    Field  `json:"escrowKey"`
	RecordUpdate
}

type UpdateMembersParams struct {
	CircuitType     string          `json:"circuitType"`
	PublicInputHash Field           `json:"publicInputHash"`
	OldRoot         Field           `json:"oldRoot"`
	NewRoot         Field           `json:"newRoot"`
	ItemCount       uint8           `json:"itemCount"`
	Items           []*MemberUpdate `json:"items"`
}

type DepositParams struct {
	CircuitType        string           `json:"circuitType"`
	PublicInputHash    Field            `json:"publicInputHash"`
	ContextHash        Field            `json:"contextHash"`
	Count              uint32           `json:"count"`
	OwnerPkHashes      []Field          `json:"ownerPkHashes"`
	NullifierPks       []Field          `json:"nullifierPks"`
	Blindings          []Field          `json:"blindings"`
	CtHashes           []Field          `json:"ctHashes"`
	Members            []*RecordOpening `json:"members"`
	EphSk              Bytes            `json:"ephSk"`
	AuditorPk          Bytes            `json:"auditorPk"`
	KeyEscrow          bool             `json:"keyEscrow"`
	MemberRegistryRoot Field            `json:"memberRegistryRoot"`
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
