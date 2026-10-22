package custom_ring

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Request fields carry the circuit field names, their tags the wire names.

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

type AuditParams struct {
	FirstNullifier Field `json:"firstNullifier"`
	RingProgramID  Field `json:"ringId"`
	TxViewingSk    Bytes `json:"txViewingSk"`
	EphSk          Bytes `json:"ephSk"`
	AuditorPk      Bytes `json:"auditorPk"`
	Salt           Bytes `json:"salt"`
	SeedOut        Field `json:"seedOut"`
	Layout         uint8 `json:"layout"`
}

type PackedAuditParams struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash Field  `json:"publicInputHash"`
	AuditParams
	NOut      uint8     `json:"nOut"`
	Outputs   []Opening `json:"outputs"`
	OwnerKeys []Bytes   `json:"ownerKeys"`
}

type DeliveredOutput struct {
	Output       Opening `json:"output"`
	AssetAddress Bytes   `json:"assetAddress"`
	RecipientKey Bytes   `json:"recipientKey"`
	OwnerKey     Bytes   `json:"ownerKey"`
	Body         Bytes   `json:"body"`
}

type DeliveredAuditParams struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash Field  `json:"publicInputHash"`
	AuditParams
	Outputs []DeliveredOutput `json:"outputs"`
}

type Stream struct {
	Tag   Field `json:"tag"`
	Inbox bool  `json:"inbox"`
	Pair  bool  `json:"pair"`
	Self  bool  `json:"self"`
	Index uint8 `json:"index"`
}

type AnonymousOutput struct {
	DeliveredOutput
	Stream Stream `json:"stream"`
}

type Anchor struct {
	TreeID         Field   `json:"treeId"`
	Asset          Field   `json:"asset"`
	Amount         Field   `json:"amount"`
	SlotSecret     Field   `json:"slotSecret"`
	FirstNullifier Field   `json:"firstNullifier"`
	SlotIndex      uint8   `json:"slotIndex"`
	Epoch          uint64  `json:"epoch"`
	Index          uint8   `json:"index"`
	PathIndex      uint64  `json:"pathIndex"`
	Path           []Field `json:"path"`
}

type AnonymousAuditParams struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash Field  `json:"publicInputHash"`
	AuditParams
	Outputs           []AnonymousOutput `json:"outputs"`
	PrivateTxHash     Field             `json:"privateTxHash"`
	PrivateTxBlinding Field             `json:"privateTxBlinding"`
	// SenderKey is the hidden owner's key on an entry key and absent on a commitment key.
	SenderKey  Bytes `json:"senderKey,omitempty"`
	InputCount uint8 `json:"inputCount"`
	// Inputs fill the input class, the slots past InputCount carry no UTXO.
	Inputs           []Opening `json:"inputs"`
	SenderCommitment Field     `json:"senderCommitment"`
	Epoch            uint64    `json:"epoch"`
	FirstContactRoot Field     `json:"firstContactRoot"`
	// An absent anchor assigns zeros.
	Anchor *Anchor `json:"anchor,omitempty"`
}

type Source struct {
	ListID uint8 `json:"listId"`
	// Registry is zero for a list the ring's own registry serves, else the curator registry address.
	Registry Field `json:"registry"`
}

type OutflowLimit struct {
	Asset       Field `json:"asset"`
	Cap         Field `json:"cap"`
	CosignAbove Field `json:"cosignAbove"`
}

type PolicyTable struct {
	Sources      []Source       `json:"sources"`
	PolicyLen    uint8          `json:"policyLen"`
	Rules        []Field        `json:"rules"`
	InlineAssets []Field        `json:"inlineAssets"`
	InlineLimits []Field        `json:"inlineLimits"`
	InlineCount  uint8          `json:"inlineCount"`
	Limits       []OutflowLimit `json:"limits"`
	LimitCount   uint8          `json:"limitCount"`
}

type OutputOpening struct {
	Opening
	// CtHash is the hash of the owner's escrowed key ciphertext, absent without escrow.
	CtHash *Field `json:"ctHash,omitempty"`
}

// RecordOpening opens a member's record in a member registry, Path the three siblings of every level from the leaf up in child order.
type RecordOpening struct {
	Next      Field   `json:"next"`
	Lists     uint64  `json:"lists"`
	EscrowKey Field   `json:"escrowKey"`
	Index     uint64  `json:"index"`
	Path      []Field `json:"path"`
}

// MemberOpening proves a member present, or absent under its low record, nil only for a slot that is no live UTXO.
type MemberOpening struct {
	Present bool `json:"present"`
	RecordOpening
	LowMember Field  `json:"lowMember"`
	LowNext   Field  `json:"lowNext"`
	LowLists  uint64 `json:"lowLists"`
	LowEscrow Field  `json:"lowEscrow"`
}

type Entry struct {
	Own     *MemberOpening `json:"own"`
	Curator *MemberOpening `json:"curator"`
}

type PolicyParams struct {
	PrivateTxHash Field   `json:"privateTxHash"`
	PolicyHash    Field   `json:"policyHash"`
	RingProgramID Field   `json:"ringId"`
	OwnRoot       Field   `json:"ownRoot"`
	CuratorRoot   Field   `json:"curatorRoot"`
	PublicAssets  []Field `json:"publicAssets"`
	PublicAmounts []Field `json:"publicAmounts"`
	PolicyTable
	AddressChain      Field           `json:"addressChain"`
	PrivateTxBlinding Field           `json:"privateTxBlinding"`
	Outputs           []OutputOpening `json:"outputs"`
	SenderPkHash      Field           `json:"senderPkHash"`
	SenderEntry       Entry           `json:"senderEntry"`
	// OwnerEntries[o] and AssetEntries[o] open output o's owner and asset.
	OwnerEntries []Entry `json:"ownerEntries"`
	AssetEntries []Entry `json:"assetEntries"`
}

type MemberPolicyParams struct {
	CircuitType      string `json:"circuitType"`
	PublicInputHash  Field  `json:"publicInputHash"`
	Anonymous        bool   `json:"anonymous"`
	ApprovalRequired bool   `json:"approvalRequired"`
	KeyEscrow        bool   `json:"keyEscrow"`
	Sender           Field  `json:"sender"`
	InputChain       Field  `json:"inputChain"`
	PolicyParams
}

type DelegatePolicyParams struct {
	CircuitType     string    `json:"circuitType"`
	PublicInputHash Field     `json:"publicInputHash"`
	Inputs          []Opening `json:"inputs"`
	PolicyParams
}

type QueueEntry struct {
	Member    Field  `json:"member"`
	Mask      uint64 `json:"mask"`
	Value     uint64 `json:"value"`
	EscrowKey Field  `json:"escrowKey"`
}

type RecordWrite struct {
	Entry     QueueEntry `json:"entry"`
	Exists    bool       `json:"exists"`
	OldNext   Field      `json:"oldNext"`
	OldLists  uint64     `json:"oldLists"`
	OldEscrow Field      `json:"oldEscrow"`
	// Index and Path open the member's leaf or the leaf an insert takes.
	Index     uint64  `json:"index"`
	Path      []Field `json:"path"`
	LowMember Field   `json:"lowMember"`
	LowNext   Field   `json:"lowNext"`
	LowLists  uint64  `json:"lowLists"`
	LowEscrow Field   `json:"lowEscrow"`
	// LowIndex and LowPath open the low record.
	LowIndex uint64  `json:"lowIndex"`
	LowPath  []Field `json:"lowPath"`
}

type ApplyRecordsParams struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash Field  `json:"publicInputHash"`
	OldRoot         Field  `json:"oldRoot"`
	NewRoot         Field  `json:"newRoot"`
	OldNextIndex    uint32 `json:"oldNextIndex"`
	NewNextIndex    uint32 `json:"newNextIndex"`
	ChainStart      Field  `json:"chainStart"`
	ChainEnd        Field  `json:"chainEnd"`
	Count           uint8  `json:"count"`
	// A nil write past Count assigns zeros.
	Writes []*RecordWrite `json:"writes"`
}

type KeyRegisterParams struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash Field  `json:"publicInputHash"`
	Member          Field  `json:"member"`
	NullifierSecret Bytes  `json:"nullifierSecret"`
	EphSk           Bytes  `json:"ephSk"`
	AuditorPk       Bytes  `json:"auditorPk"`
}

// DepositParams carries Ed25519 owner keys only for anonymous deposits.
type DepositParams struct {
	CircuitType        string           `json:"circuitType"`
	PublicInputHash    Field            `json:"publicInputHash"`
	ContextHash        Field            `json:"contextHash"`
	Count              uint32           `json:"count"`
	Anonymous          bool             `json:"anonymous,omitempty"`
	OwnerPkHashes      []Field          `json:"ownerPkHashes"`
	OwnerKeys          *[]Bytes         `json:"ownerKeys,omitempty"`
	NullifierPks       []Field          `json:"nullifierPks"`
	BlindingSecrets    []Field          `json:"blindingSecrets"`
	CtHashes           []Field          `json:"ctHashes"`
	Members            []*RecordOpening `json:"members"`
	EphSk              Bytes            `json:"ephSk"`
	AuditorPk          Bytes            `json:"auditorPk"`
	KeyEscrow          bool             `json:"keyEscrow"`
	MemberRegistryRoot Field            `json:"memberRegistryRoot"`
}

// MergeInput is one SPP merge slot as the anonymous merge circuit opens it.
type MergeInput struct {
	Domain       Field `json:"domain"`
	TreeID       Field `json:"treeId"`
	Amount       Field `json:"amount"`
	Blinding     Field `json:"blinding"`
	RingDataHash Field `json:"ringDataHash"`
}

// AnonymousMergeParams discloses an anonymous ring's SPP merge to its auditor.
type AnonymousMergeParams struct {
	CircuitType        string       `json:"circuitType"`
	PublicInputHash    Field        `json:"publicInputHash"`
	PrivateTxHash      Field        `json:"privateTxHash"`
	OutputUtxoHash     Field        `json:"outputUtxoHash"`
	FirstNullifier     Field        `json:"firstNullifier"`
	RingProgramID      Field        `json:"ringProgramId"`
	AuditorPk          Bytes        `json:"auditorPk"`
	Salt               Field        `json:"salt"`
	EphSk              Bytes        `json:"ephSk"`
	DisclosureKey      Bytes        `json:"disclosureKey"`
	OwnerKey           Bytes        `json:"ownerKey"`
	NullifierSecret    Field        `json:"nullifierSecret"`
	MintChunks         []Field      `json:"mintChunks"`
	Inputs             []MergeInput `json:"inputs"`
	OutputTreeID       Field        `json:"outputTreeId"`
	OutputRingDataHash Field        `json:"outputRingDataHash"`
}

// Unmarshal decodes a request whose keys name fields of v exactly and once, with nothing after it.
func Unmarshal(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := strictly(decoder, reflect.TypeOf(v).Elem(), 0); err != nil {
		return fmt.Errorf("custom-ring: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("custom-ring: trailing data after the request")
	}
	return json.Unmarshal(data, v)
}

const maxDepth = 32

var unmarshaler = reflect.TypeFor[json.Unmarshaler]()

// strictly reads one value of t, refusing a key without an exact field, a repeated key and a null t cannot hold.
func strictly(decoder *json.Decoder, t reflect.Type, depth int) error {
	if depth > maxDepth {
		return errors.New("nested too deeply")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	nullable := t.Kind() == reflect.Pointer
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	custom := reflect.PointerTo(t).Implements(unmarshaler)
	if token == nil {
		if nullable || custom {
			return nil
		}
		return errors.New("null value")
	}
	if !custom {
		switch t.Kind() {
		case reflect.Struct:
			return strictObject(decoder, t, token, depth)
		case reflect.Slice, reflect.Array:
			return strictArray(decoder, t, token, depth)
		}
	}
	if _, composite := token.(json.Delim); composite {
		return errors.New("expected a scalar")
	}
	return nil
}

func strictObject(decoder *json.Decoder, t reflect.Type, token json.Token, depth int) error {
	if token != json.Delim('{') {
		return errors.New("expected an object")
	}
	fields := make(map[string]reflect.Type)
	jsonFields(t, fields)
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name, _ := key.(string)
		field, known := fields[name]
		if !known {
			return fmt.Errorf("unknown field %q", name)
		}
		if seen[name] {
			return fmt.Errorf("repeated field %q", name)
		}
		seen[name] = true
		if err := strictly(decoder, field, depth+1); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	_, err := decoder.Token()
	return err
}

func strictArray(decoder *json.Decoder, t reflect.Type, token json.Token, depth int) error {
	if token != json.Delim('[') {
		return errors.New("expected an array")
	}
	for i := 0; decoder.More(); i++ {
		if err := strictly(decoder, t.Elem(), depth+1); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	_, err := decoder.Token()
	return err
}

// jsonFields maps t's JSON keys to their types, promoting untagged embedded structs as encoding/json does.
func jsonFields(t reflect.Type, fields map[string]reflect.Type) {
	for i := range t.NumField() {
		field := t.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if field.Anonymous && name == "" && field.Type.Kind() == reflect.Struct {
			jsonFields(field.Type, fields)
			continue
		}
		if name == "-" || !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
}
