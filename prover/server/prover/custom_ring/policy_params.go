package custom_ring

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
)

const (
	scalarLen             = 32
	uncompressedPubkeyLen = 65
	ruleEncLen            = 32
)

// Opening is one UTXO slot the statement opens, ordered as the circuit
// hashes it.
type Opening struct {
	Domain        *big.Int
	TreeID        *big.Int
	OwnerPkHash   *big.Int
	NullifierPk   *big.Int
	Asset         *big.Int
	Amount        *big.Int
	Blinding      *big.Int
	DataHash      *big.Int
	RingDataHash  *big.Int
	RingProgramID *big.Int
}

// ListFact supplies a presence or absence claim for circuit verification.
type ListFact struct {
	Enabled      bool
	Mode         uint8
	ListId       uint8
	State        uint8
	AbsentBranch uint8
	Member       *big.Int
	ContentHash  *big.Int
	Version      uint64
	Blinding     *big.Int
	Low          *big.Int
	Next         *big.Int

	NfPathElements [shared.NullifierTreeHeight]*big.Int
	NfPathIndex    uint64

	StatePathElements [shared.StateTreeHeight]*big.Int
	StatePathIndex    uint64
}

// SourceOwner is one slot of the positional source map, slot i empty or
// serving list i+1.
type SourceOwner struct {
	ListId    uint8
	OwnerHash *big.Int
}

type VelocityRow struct {
	Asset       *big.Int
	Cap         *big.Int
	CosignAbove *big.Int
}

// SpendRecord supplies private counter openings without authenticating the record's current head.
type SpendRecord struct {
	Version    uint64
	Window     uint64
	Commitment *big.Int
	Salt       *big.Int
	Assets     [policy.NVelocityAssets]*big.Int
	Spent      [policy.NVelocityAssets]*big.Int
	NextSalt   *big.Int
}

type PolicyParameters struct {
	PublicInputHash *big.Int
	PrivateTxHash   *big.Int
	TxViewingSk     [scalarLen]byte
	EphSk           [scalarLen]byte
	AuditorPk       [uncompressedPubkeyLen]byte
	Salt            [16]byte

	NIn     uint8
	NOut    uint8
	Inputs  [policy.NInputs]Opening
	Outputs [policy.NOutputs]Opening

	AddressChain      *big.Int
	ExternalDataHash  *big.Int
	PrivateTxBlinding *big.Int

	Sources       [policy.NSources]SourceOwner
	PolicyLen     uint8
	RuleEnc       [policy.NRules][ruleEncLen]byte
	InlineAssets  [policy.NInlineAssets]*big.Int
	InlineLimits  [policy.NInlineAssets]*big.Int
	InlineCount   uint8
	WindowSlots   uint64
	Velocity      [policy.NVelocityAssets]VelocityRow
	VelocityCount uint8

	StateRoot          *big.Int
	NullifierRoot      *big.Int
	EntriesTreeID      *big.Int
	RingID             *big.Int
	NamespaceOwnerHash *big.Int
	WindowIndex        uint64
	ApprovalRequired   bool
	Record             SpendRecord

	ListFacts [policy.NListFacts]ListFact
}

type openingJSON struct {
	Domain        string `json:"domain"`
	TreeID        string `json:"treeId"`
	OwnerPkHash   string `json:"ownerPkHash"`
	NullifierPk   string `json:"nullifierPk"`
	Asset         string `json:"asset"`
	Amount        string `json:"amount"`
	Blinding      string `json:"blinding"`
	DataHash      string `json:"dataHash"`
	RingDataHash  string `json:"ringDataHash"`
	RingProgramID string `json:"ringProgramId"`
}

type sourceOwnerJSON struct {
	ListId    uint8  `json:"listId"`
	OwnerHash string `json:"ownerHash"`
}

type velocityRowJSON struct {
	Asset       string `json:"asset"`
	Cap         string `json:"cap"`
	CosignAbove string `json:"cosignAbove"`
}

type spendRecordJSON struct {
	Version    uint64   `json:"version"`
	Window     uint64   `json:"window"`
	Commitment string   `json:"commitment"`
	Salt       string   `json:"salt"`
	Assets     []string `json:"assets"`
	Spent      []string `json:"spent"`
	NextSalt   string   `json:"nextSalt"`
}

type listFactJSON struct {
	Enabled           bool     `json:"enabled"`
	Mode              uint8    `json:"mode"`
	ListId            uint8    `json:"listId"`
	State             uint8    `json:"state"`
	AbsentBranch      uint8    `json:"absentBranch"`
	Member            string   `json:"member"`
	ContentHash       string   `json:"contentHash"`
	Version           uint64   `json:"version"`
	Blinding          string   `json:"blinding"`
	Low               string   `json:"low"`
	Next              string   `json:"next"`
	NfPathElements    []string `json:"nfPathElements"`
	NfPathIndex       uint64   `json:"nfPathIndex"`
	StatePathElements []string `json:"statePathElements"`
	StatePathIndex    uint64   `json:"statePathIndex"`
}

type policyParametersJSON struct {
	CircuitType        string            `json:"circuitType"`
	PublicInputHash    string            `json:"publicInputHash"`
	PrivateTxHash      string            `json:"privateTxHash"`
	TxViewingSk        string            `json:"txViewingSk"`
	EphSk              string            `json:"ephSk"`
	AuditorPk          string            `json:"auditorPk"`
	Salt               string            `json:"salt"`
	NIn                uint8             `json:"nIn"`
	NOut               uint8             `json:"nOut"`
	Inputs             []openingJSON     `json:"inputs"`
	Outputs            []openingJSON     `json:"outputs"`
	AddressChain       string            `json:"addressChain"`
	ExternalDataHash   string            `json:"externalDataHash"`
	PrivateTxBlinding  string            `json:"privateTxBlinding"`
	Sources            []sourceOwnerJSON `json:"sources"`
	PolicyLen          uint8             `json:"policyLen"`
	RuleEnc            []string          `json:"ruleEnc"`
	InlineAssets       []string          `json:"inlineAssets"`
	InlineLimits       []string          `json:"inlineLimits"`
	InlineCount        uint8             `json:"inlineCount"`
	WindowSlots        uint64            `json:"windowSlots"`
	Velocity           []velocityRowJSON `json:"velocity"`
	VelocityCount      uint8             `json:"velocityCount"`
	StateRoot          string            `json:"stateRoot"`
	NullifierRoot      string            `json:"nullifierRoot"`
	EntriesTreeID      string            `json:"entriesTreeId"`
	RingID             string            `json:"ringId"`
	NamespaceOwnerHash string            `json:"namespaceOwnerHash"`
	WindowIndex        uint64            `json:"windowIndex"`
	ApprovalRequired   bool              `json:"approvalRequired"`
	Record             spendRecordJSON   `json:"record"`
	ListFacts          []listFactJSON    `json:"answers"`
}

func (p *PolicyParameters) MarshalJSON() ([]byte, error) {
	raw := policyParametersJSON{
		CircuitType:        string(common.CustomRingPolicyCircuitType),
		PublicInputHash:    common.ToHex(p.PublicInputHash),
		PrivateTxHash:      common.ToHex(p.PrivateTxHash),
		TxViewingSk:        bytesHex(p.TxViewingSk[:]),
		EphSk:              bytesHex(p.EphSk[:]),
		AuditorPk:          bytesHex(p.AuditorPk[:]),
		Salt:               bytesHex(p.Salt[:]),
		NIn:                p.NIn,
		NOut:               p.NOut,
		Inputs:             writeOpenings(p.Inputs[:]),
		Outputs:            writeOpenings(p.Outputs[:]),
		AddressChain:       common.ToHex(p.AddressChain),
		ExternalDataHash:   common.ToHex(p.ExternalDataHash),
		PrivateTxBlinding:  common.ToHex(p.PrivateTxBlinding),
		Sources:            make([]sourceOwnerJSON, 0, len(p.Sources)),
		PolicyLen:          p.PolicyLen,
		RuleEnc:            make([]string, 0, len(p.RuleEnc)),
		InlineAssets:       make([]string, 0, len(p.InlineAssets)),
		InlineLimits:       make([]string, 0, len(p.InlineLimits)),
		InlineCount:        p.InlineCount,
		WindowSlots:        p.WindowSlots,
		Velocity:           make([]velocityRowJSON, 0, len(p.Velocity)),
		VelocityCount:      p.VelocityCount,
		StateRoot:          common.ToHex(p.StateRoot),
		NullifierRoot:      common.ToHex(p.NullifierRoot),
		EntriesTreeID:      common.ToHex(p.EntriesTreeID),
		RingID:             common.ToHex(p.RingID),
		NamespaceOwnerHash: common.ToHex(p.NamespaceOwnerHash),
		WindowIndex:        p.WindowIndex,
		ApprovalRequired:   p.ApprovalRequired,
		Record: spendRecordJSON{
			Version:    p.Record.Version,
			Window:     p.Record.Window,
			Commitment: common.ToHex(p.Record.Commitment),
			Salt:       common.ToHex(p.Record.Salt),
			Assets:     writePath(p.Record.Assets[:]),
			Spent:      writePath(p.Record.Spent[:]),
			NextSalt:   common.ToHex(p.Record.NextSalt),
		},
		ListFacts: make([]listFactJSON, 0, len(p.ListFacts)),
	}
	for _, row := range p.Velocity {
		raw.Velocity = append(raw.Velocity, velocityRowJSON{
			Asset:       common.ToHex(row.Asset),
			Cap:         common.ToHex(row.Cap),
			CosignAbove: common.ToHex(row.CosignAbove),
		})
	}
	for _, src := range p.Sources {
		raw.Sources = append(raw.Sources, sourceOwnerJSON{
			ListId:    src.ListId,
			OwnerHash: common.ToHex(src.OwnerHash),
		})
	}
	for _, encoded := range p.RuleEnc {
		raw.RuleEnc = append(raw.RuleEnc, bytesHex(encoded[:]))
	}
	for _, asset := range p.InlineAssets {
		raw.InlineAssets = append(raw.InlineAssets, common.ToHex(asset))
	}
	for _, limit := range p.InlineLimits {
		raw.InlineLimits = append(raw.InlineLimits, common.ToHex(limit))
	}
	for i := range p.ListFacts {
		raw.ListFacts = append(raw.ListFacts, writeListFact(&p.ListFacts[i]))
	}
	return json.Marshal(raw)
}

func (p *PolicyParameters) UnmarshalJSON(data []byte) error {
	var raw policyParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.CustomRingPolicyCircuitType) {
		return fmt.Errorf("custom-ring-policy: unexpected circuitType %q", raw.CircuitType)
	}
	if raw.NIn == 0 || int(raw.NIn) > policy.NInputs {
		return fmt.Errorf("custom-ring: nIn %d is outside 1..%d", raw.NIn, policy.NInputs)
	}
	if raw.NOut == 0 || int(raw.NOut) > policy.NOutputs {
		return fmt.Errorf("custom-ring: nOut %d is outside 1..%d", raw.NOut, policy.NOutputs)
	}
	if int(raw.PolicyLen) > policy.NRules {
		return fmt.Errorf("custom-ring: policyLen %d exceeds %d", raw.PolicyLen, policy.NRules)
	}
	if int(raw.InlineCount) > policy.NInlineAssets {
		return fmt.Errorf("custom-ring: inlineCount %d exceeds %d", raw.InlineCount, policy.NInlineAssets)
	}
	if int(raw.VelocityCount) > policy.NVelocityAssets {
		return fmt.Errorf("custom-ring: velocityCount %d exceeds %d", raw.VelocityCount, policy.NVelocityAssets)
	}
	if raw.WindowSlots != 0 && raw.VelocityCount == 0 {
		return fmt.Errorf("custom-ring: a window needs velocity rows")
	}

	var err error
	if p.PublicInputHash, err = fieldFromHex(raw.PublicInputHash, "publicInputHash"); err != nil {
		return err
	}
	if p.PrivateTxHash, err = fieldFromHex(raw.PrivateTxHash, "privateTxHash"); err != nil {
		return err
	}
	if err = bytesFromHex(p.TxViewingSk[:], raw.TxViewingSk, "txViewingSk"); err != nil {
		return err
	}
	if err = validateP256Scalar(p.TxViewingSk[:], "txViewingSk"); err != nil {
		return err
	}
	if err = bytesFromHex(p.EphSk[:], raw.EphSk, "ephSk"); err != nil {
		return err
	}
	if err = validateP256Scalar(p.EphSk[:], "ephSk"); err != nil {
		return err
	}
	if err = bytesFromHex(p.AuditorPk[:], raw.AuditorPk, "auditorPk"); err != nil {
		return err
	}
	if x, y := elliptic.Unmarshal(elliptic.P256(), p.AuditorPk[:]); x == nil || y == nil {
		return fmt.Errorf("custom-ring: auditorPk is not a P256 point")
	}
	if err = bytesFromHex(p.Salt[:], raw.Salt, "salt"); err != nil {
		return err
	}
	if p.AddressChain, err = fieldFromHex(raw.AddressChain, "addressChain"); err != nil {
		return err
	}
	if p.ExternalDataHash, err = fieldFromHex(raw.ExternalDataHash, "externalDataHash"); err != nil {
		return err
	}
	if p.PrivateTxBlinding, err = fieldFromHex(raw.PrivateTxBlinding, "privateTxBlinding"); err != nil {
		return err
	}
	if len(raw.Sources) != policy.NSources {
		return fmt.Errorf("custom-ring: sources holds %d slots, expected %d", len(raw.Sources), policy.NSources)
	}
	for i, src := range raw.Sources {
		owner, err := fieldFromHex(src.OwnerHash, "sources")
		if err != nil {
			return err
		}
		// Mirrors ring_policy::SourceMap::from_slots.
		empty := src.ListId == 0 && owner.Sign() == 0
		positional := int(src.ListId) == i+1 && owner.Sign() != 0
		if !empty && !positional {
			return fmt.Errorf("custom-ring: sources slot %d breaks the positional layout", i)
		}
		p.Sources[i] = SourceOwner{ListId: src.ListId, OwnerHash: owner}
	}
	if p.StateRoot, err = fieldFromHex(raw.StateRoot, "stateRoot"); err != nil {
		return err
	}
	if p.NullifierRoot, err = fieldFromHex(raw.NullifierRoot, "nullifierRoot"); err != nil {
		return err
	}
	if p.EntriesTreeID, err = fieldFromHex(raw.EntriesTreeID, "entriesTreeId"); err != nil {
		return err
	}
	if p.RingID, err = fieldFromHex(raw.RingID, "ringId"); err != nil {
		return err
	}
	if p.NamespaceOwnerHash, err = fieldFromHex(raw.NamespaceOwnerHash, "namespaceOwnerHash"); err != nil {
		return err
	}
	if err = readVelocity(p.Velocity[:], raw.Velocity, raw.VelocityCount); err != nil {
		return err
	}
	if err = readRecord(&p.Record, raw.Record); err != nil {
		return err
	}
	p.WindowSlots, p.WindowIndex, p.ApprovalRequired = raw.WindowSlots, raw.WindowIndex, raw.ApprovalRequired

	p.NIn, p.NOut, p.PolicyLen, p.InlineCount, p.VelocityCount = raw.NIn, raw.NOut, raw.PolicyLen, raw.InlineCount, raw.VelocityCount
	if err = readOpenings(p.Inputs[:], raw.Inputs, "inputs"); err != nil {
		return err
	}
	if err = readOpenings(p.Outputs[:], raw.Outputs, "outputs"); err != nil {
		return err
	}
	if len(raw.RuleEnc) != policy.NRules {
		return fmt.Errorf("custom-ring: ruleEnc holds %d rules, expected %d", len(raw.RuleEnc), policy.NRules)
	}
	for i, encoded := range raw.RuleEnc {
		if err = bytesFromHex(p.RuleEnc[i][:], encoded, "ruleEnc"); err != nil {
			return err
		}
	}
	if len(raw.InlineAssets) != policy.NInlineAssets {
		return fmt.Errorf("custom-ring: inlineAssets holds %d entries, expected %d", len(raw.InlineAssets), policy.NInlineAssets)
	}
	if len(raw.InlineLimits) != policy.NInlineAssets {
		return fmt.Errorf("custom-ring: inlineLimits holds %d entries, expected %d", len(raw.InlineLimits), policy.NInlineAssets)
	}
	for i, limit := range raw.InlineLimits {
		if p.InlineLimits[i], err = fieldFromHex(limit, "inlineLimits"); err != nil {
			return err
		}
		if p.InlineLimits[i].BitLen() > 64 {
			return fmt.Errorf("custom-ring: inlineLimits[%d] exceeds 64 bits", i)
		}
		if i >= int(raw.InlineCount) && p.InlineLimits[i].Sign() != 0 {
			return fmt.Errorf("custom-ring: inlineLimits[%d] is non-zero padding after inlineCount %d", i, raw.InlineCount)
		}
	}
	for i, asset := range raw.InlineAssets {
		if p.InlineAssets[i], err = fieldFromHex(asset, "inlineAssets"); err != nil {
			return err
		}
		if i >= int(raw.InlineCount) && p.InlineAssets[i].Sign() != 0 {
			return fmt.Errorf("custom-ring: inlineAssets[%d] is non-zero padding after inlineCount %d", i, raw.InlineCount)
		}
	}
	if len(raw.ListFacts) != policy.NListFacts {
		return fmt.Errorf("custom-ring: answers holds %d entries, expected %d", len(raw.ListFacts), policy.NListFacts)
	}
	for i, fact := range raw.ListFacts {
		if err = readListFact(&p.ListFacts[i], fact); err != nil {
			return err
		}
	}
	return nil
}

func writeOpenings(src []Opening) []openingJSON {
	out := make([]openingJSON, len(src))
	for i, slot := range src {
		out[i] = openingJSON{
			Domain:        common.ToHex(slot.Domain),
			TreeID:        common.ToHex(slot.TreeID),
			OwnerPkHash:   common.ToHex(slot.OwnerPkHash),
			NullifierPk:   common.ToHex(slot.NullifierPk),
			Asset:         common.ToHex(slot.Asset),
			Amount:        common.ToHex(slot.Amount),
			Blinding:      common.ToHex(slot.Blinding),
			DataHash:      common.ToHex(slot.DataHash),
			RingDataHash:  common.ToHex(slot.RingDataHash),
			RingProgramID: common.ToHex(slot.RingProgramID),
		}
	}
	return out
}

func writeListFact(src *ListFact) listFactJSON {
	return listFactJSON{
		Enabled:           src.Enabled,
		Mode:              src.Mode,
		ListId:            src.ListId,
		State:             src.State,
		AbsentBranch:      src.AbsentBranch,
		Member:            common.ToHex(src.Member),
		ContentHash:       common.ToHex(src.ContentHash),
		Version:           src.Version,
		Blinding:          common.ToHex(src.Blinding),
		Low:               common.ToHex(src.Low),
		Next:              common.ToHex(src.Next),
		NfPathElements:    writePath(src.NfPathElements[:]),
		NfPathIndex:       src.NfPathIndex,
		StatePathElements: writePath(src.StatePathElements[:]),
		StatePathIndex:    src.StatePathIndex,
	}
}

func writePath(src []*big.Int) []string {
	out := make([]string, len(src))
	for i, node := range src {
		out[i] = common.ToHex(node)
	}
	return out
}

func readOpenings(dst []Opening, src []openingJSON, name string) error {
	if len(src) != len(dst) {
		return fmt.Errorf("custom-ring: %s holds %d slots, expected %d", name, len(src), len(dst))
	}
	for i, slot := range src {
		fields := []struct {
			target **big.Int
			value  string
			label  string
		}{
			{&dst[i].Domain, slot.Domain, "domain"},
			{&dst[i].TreeID, slot.TreeID, "treeId"},
			{&dst[i].OwnerPkHash, slot.OwnerPkHash, "ownerPkHash"},
			{&dst[i].NullifierPk, slot.NullifierPk, "nullifierPk"},
			{&dst[i].Asset, slot.Asset, "asset"},
			{&dst[i].Amount, slot.Amount, "amount"},
			{&dst[i].Blinding, slot.Blinding, "blinding"},
			{&dst[i].DataHash, slot.DataHash, "dataHash"},
			{&dst[i].RingDataHash, slot.RingDataHash, "ringDataHash"},
			{&dst[i].RingProgramID, slot.RingProgramID, "ringProgramId"},
		}
		for _, field := range fields {
			value, err := fieldFromHex(field.value, field.label)
			if err != nil {
				return err
			}
			*field.target = value
		}
	}
	return nil
}

func readVelocity(dst []VelocityRow, src []velocityRowJSON, count uint8) error {
	if len(src) != len(dst) {
		return fmt.Errorf("custom-ring: velocity holds %d rows, expected %d", len(src), len(dst))
	}
	for i, row := range src {
		var err error
		if dst[i].Asset, err = fieldFromHex(row.Asset, "velocity asset"); err != nil {
			return err
		}
		if dst[i].Cap, err = amountFromHex(row.Cap, "velocity cap"); err != nil {
			return err
		}
		if dst[i].CosignAbove, err = amountFromHex(row.CosignAbove, "velocity cosignAbove"); err != nil {
			return err
		}
		padding := dst[i].Asset.Sign() == 0 && dst[i].Cap.Sign() == 0 && dst[i].CosignAbove.Sign() == 0
		if i >= int(count) && !padding {
			return fmt.Errorf("custom-ring: velocity[%d] is non-zero padding after velocityCount %d", i, count)
		}
	}
	return nil
}

func readRecord(dst *SpendRecord, src spendRecordJSON) error {
	dst.Version, dst.Window = src.Version, src.Window
	var err error
	if dst.Commitment, err = fieldFromHex(src.Commitment, "record commitment"); err != nil {
		return err
	}
	if dst.Salt, err = fieldFromHex(src.Salt, "record salt"); err != nil {
		return err
	}
	if dst.NextSalt, err = fieldFromHex(src.NextSalt, "record nextSalt"); err != nil {
		return err
	}
	if err = readPath(dst.Assets[:], src.Assets, "record assets"); err != nil {
		return err
	}
	if len(src.Spent) != len(dst.Spent) {
		return fmt.Errorf("custom-ring: record spent holds %d counters, expected %d", len(src.Spent), len(dst.Spent))
	}
	for i, spent := range src.Spent {
		if dst.Spent[i], err = amountFromHex(spent, "record spent"); err != nil {
			return err
		}
	}
	return nil
}

func readListFact(dst *ListFact, src listFactJSON) error {
	if src.Enabled {
		if src.Mode != policy.ModePresent && src.Mode != policy.ModeAbsent {
			return fmt.Errorf("custom-ring: answers mode %d is not present or absent", src.Mode)
		}
		if src.ListId == 0 {
			return fmt.Errorf("custom-ring: answers listId is unset")
		}
	}
	dst.Enabled = src.Enabled
	dst.Mode, dst.ListId, dst.State, dst.AbsentBranch = src.Mode, src.ListId, src.State, src.AbsentBranch
	dst.Version, dst.NfPathIndex, dst.StatePathIndex = src.Version, src.NfPathIndex, src.StatePathIndex

	var err error
	if dst.Member, err = fieldFromHex(src.Member, "member"); err != nil {
		return err
	}
	if src.Enabled && dst.Member.Sign() == 0 {
		return fmt.Errorf("custom-ring: answers member is zero")
	}
	if dst.ContentHash, err = fieldFromHex(src.ContentHash, "contentHash"); err != nil {
		return err
	}
	if dst.Blinding, err = fieldFromHex(src.Blinding, "blinding"); err != nil {
		return err
	}
	if dst.Low, err = fieldFromHex(src.Low, "low"); err != nil {
		return err
	}
	if dst.Next, err = fieldFromHex(src.Next, "next"); err != nil {
		return err
	}
	if err = readPath(dst.NfPathElements[:], src.NfPathElements, "nfPathElements"); err != nil {
		return err
	}
	return readPath(dst.StatePathElements[:], src.StatePathElements, "statePathElements")
}

func readPath(dst []*big.Int, src []string, name string) error {
	if len(src) != len(dst) {
		return fmt.Errorf("custom-ring: %s holds %d nodes, expected %d", name, len(src), len(dst))
	}
	for i, node := range src {
		value, err := fieldFromHex(node, name)
		if err != nil {
			return err
		}
		dst[i] = value
	}
	return nil
}

func (p *PolicyParameters) CreateWitness() (*policy.CustomRingPolicyCircuit, error) {
	if p.PublicInputHash == nil || p.PrivateTxHash == nil {
		return nil, fmt.Errorf("custom-ring: missing hash")
	}
	circuit := &policy.CustomRingPolicyCircuit{
		PublicInputHash:    p.PublicInputHash,
		PrivateTxHash:      p.PrivateTxHash,
		AddressChain:       p.AddressChain,
		ExternalDataHash:   p.ExternalDataHash,
		PrivateTxBlinding:  p.PrivateTxBlinding,
		WindowSlots:        p.WindowSlots,
		StateRoot:          p.StateRoot,
		NullifierRoot:      p.NullifierRoot,
		EntriesTreeID:      p.EntriesTreeID,
		RingID:             p.RingID,
		NamespaceOwnerHash: p.NamespaceOwnerHash,
		WindowIndex:        p.WindowIndex,
		ApprovalRequired:   boolVar(p.ApprovalRequired),
		Record: policy.RecordWires{
			Version:    p.Record.Version,
			Window:     p.Record.Window,
			Commitment: p.Record.Commitment,
			Salt:       p.Record.Salt,
			NextSalt:   p.Record.NextSalt,
		},
	}
	for i := range circuit.Record.Assets {
		circuit.Record.Assets[i] = p.Record.Assets[i]
		circuit.Record.Spent[i] = p.Record.Spent[i]
	}
	for i, row := range p.Velocity {
		circuit.Velocity[i] = policy.VelocityRowWires{
			Asset:       row.Asset,
			Cap:         row.Cap,
			CosignAbove: row.CosignAbove,
		}
	}
	assignOneHot(circuit.VelocityCountSelected[:], int(p.VelocityCount))
	for i, src := range p.Sources {
		circuit.Sources[i] = policy.SourceWires{
			ListId:    src.ListId,
			OwnerHash: src.OwnerHash,
		}
	}
	assignBytes(circuit.TxViewingSk[:], p.TxViewingSk[:])
	assignBytes(circuit.EphSk[:], p.EphSk[:])
	assignBytes(circuit.AuditorPk[:], p.AuditorPk[:])
	assignBytes(circuit.Salt[:], p.Salt[:])

	for i := range circuit.Inputs {
		assignOpening(&circuit.Inputs[i], &p.Inputs[i])
	}
	for i := range circuit.Outputs {
		assignOpening(&circuit.Outputs[i], &p.Outputs[i])
	}
	assignOneHot(circuit.InputCountSelected[:], int(p.NIn)-1)
	assignOneHot(circuit.OutputCountSelected[:], int(p.NOut)-1)
	assignOneHot(circuit.RuleCountSelected[:], int(p.PolicyLen))
	assignOneHot(circuit.InlineAssetCountSelected[:], int(p.InlineCount))

	for i := range circuit.Rules {
		assignRule(&circuit.Rules[i], p.RuleEnc[i])
	}
	for i := range circuit.InlineAssets {
		circuit.InlineAssets[i] = p.InlineAssets[i]
		circuit.InlineLimits[i] = p.InlineLimits[i]
	}
	for i := range circuit.ListFacts {
		assignListFact(&circuit.ListFacts[i], &p.ListFacts[i])
	}
	return circuit, nil
}

func assignOpening(dst *policy.UtxoWires, src *Opening) {
	dst.Domain = src.Domain
	dst.TreeID = src.TreeID
	dst.OwnerPkHash = src.OwnerPkHash
	dst.NullifierPk = src.NullifierPk
	dst.Asset = src.Asset
	dst.Amount = src.Amount
	dst.Blinding = src.Blinding
	dst.DataHash = src.DataHash
	dst.RingDataHash = src.RingDataHash
	dst.RingProgramID = src.RingProgramID
}

// The circuit reads a count only through its one-hot, an out-of-range set bit
// would leave every slot masked off.
func assignOneHot(dst []frontend.Variable, set int) {
	for i := range dst {
		if i == set {
			dst[i] = 1
		} else {
			dst[i] = 0
		}
	}
}

// Byte order mirrors `Rule::encoded`, byte 31 is the subject, bytes 20..28 the
// threshold and byte 19 the alt mask.
func assignRule(dst *policy.RuleWires, encoded [ruleEncLen]byte) {
	dst.Packed = new(big.Int).SetBytes(encoded[:])
	dst.Subject = encoded[31]
	dst.Mode = encoded[30]
	dst.ListMask = encoded[29]
	dst.GuardTag = encoded[28]
	dst.Threshold = new(big.Int).SetBytes(encoded[20:28])
	dst.OppositeModeListMask = encoded[19]
}

func assignListFact(dst *policy.ListFactWires, src *ListFact) {
	dst.Enabled = boolVar(src.Enabled)
	dst.Mode = src.Mode
	dst.ListId = src.ListId
	dst.Member = src.Member
	dst.ContentHash = src.ContentHash
	dst.Version = src.Version
	dst.Blinding = src.Blinding
	dst.State = src.State
	dst.AbsentBranch = src.AbsentBranch
	dst.NullifierLowValue = src.Low
	dst.NullifierNextValue = src.Next
	dst.NullifierLowPathIndex = src.NfPathIndex
	dst.StatePathIndex = src.StatePathIndex
	for i := range dst.NullifierLowPathElements {
		dst.NullifierLowPathElements[i] = src.NfPathElements[i]
	}
	for i := range dst.StatePathElements {
		dst.StatePathElements[i] = src.StatePathElements[i]
	}
}

func boolVar(value bool) frontend.Variable {
	if value {
		return 1
	}
	return 0
}

func assignBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = b
	}
}

func bytesHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

func bytesFromHex(dst []byte, s string, name string) error {
	if len(s) != 2+2*len(dst) || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return fmt.Errorf("custom-ring: %s is not canonical hex", name)
	}
	decoded, err := hex.DecodeString(s[2:])
	if err != nil {
		return fmt.Errorf("custom-ring: %s: %w", name, err)
	}
	if len(decoded) != len(dst) {
		return fmt.Errorf("custom-ring: %s: got %d bytes, expected %d", name, len(decoded), len(dst))
	}
	copy(dst, decoded)
	return nil
}

func validateP256Scalar(value []byte, name string) error {
	scalar := new(big.Int).SetBytes(value)
	if scalar.Sign() == 0 || scalar.Cmp(elliptic.P256().Params().N) >= 0 {
		return fmt.Errorf("custom-ring: %s is not a canonical P256 scalar", name)
	}
	return nil
}

func validateP256Point(value []byte, name string) error {
	if x, y := elliptic.Unmarshal(elliptic.P256(), value); x == nil || y == nil {
		return fmt.Errorf("custom-ring: %s is not a P256 point", name)
	}
	return nil
}

// Amounts and counters are unsigned 64-bit, the circuit range checks the same width.
func amountFromHex(s string, name string) (*big.Int, error) {
	value, err := fieldFromHex(s, name)
	if err != nil {
		return nil, err
	}
	if value.BitLen() > 64 {
		return nil, fmt.Errorf("custom-ring: %s exceeds 64 bits", name)
	}
	return value, nil
}

// Canonical fields prevent silent modular reduction.
func fieldFromHex(s string, name string) (*big.Int, error) {
	if len(s) != 66 || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return nil, fmt.Errorf("custom-ring: %s is not canonical hex", name)
	}
	v := new(big.Int)
	if err := common.FromHex(v, s); err != nil {
		return nil, fmt.Errorf("custom-ring: %s: %w", name, err)
	}
	if v.Sign() < 0 || v.Cmp(ecc.BN254.ScalarField()) >= 0 {
		return nil, fmt.Errorf("custom-ring: %s is not a canonical field element", name)
	}
	return v, nil
}
