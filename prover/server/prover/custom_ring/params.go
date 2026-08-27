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

	"zolana/prover/circuits/custom_ring/transfer"
	"zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
)

const (
	scalarLen             = 32
	uncompressedPubkeyLen = 65
	TransferVariant       = "transfer"

	ruleEncLen   = 32
	activeState  = 1
	clearedState = 2
)

// Opening is one UTXO slot the statement opens, ordered as the circuit
// hashes it.
type Opening struct {
	Domain        *big.Int
	OwnerPkHash   *big.Int
	NullifierPk   *big.Int
	Asset         *big.Int
	Amount        *big.Int
	Blinding      *big.Int
	DataHash      *big.Int
	RingDataHash  *big.Int
	RingProgramID *big.Int
}

// Answer is one entry fact the statement proves against the roots.
type Answer struct {
	Enabled      bool
	Mode         uint8
	ListId         uint8
	State        uint8
	AbsentBranch uint8
	Member       *big.Int
	ContentHash  *big.Int
	Version      uint64
	Low          *big.Int
	Next         *big.Int

	NfPathElements [shared.NullifierTreeHeight]*big.Int
	NfPathIndex    uint64

	StatePathElements [shared.StateTreeHeight]*big.Int
	StatePathIndex    uint64
}

// SourceOwner is one slot of the positional source map, slot i empty or
// serving listId i+1.
type SourceOwner struct {
	ListId      uint8
	OwnerHash *big.Int
}

type CustomRingParameters struct {
	PublicInputHash *big.Int
	PrivateTxHash   *big.Int
	TxViewingSk     [scalarLen]byte
	EphSk           [scalarLen]byte
	AuditorPk       [uncompressedPubkeyLen]byte

	NIn     uint8
	NOut    uint8
	Inputs  [transfer.NIn]Opening
	Outputs [transfer.NOut]Opening

	AddressChain     *big.Int
	ExternalDataHash *big.Int

	Sources      [transfer.NSources]SourceOwner
	PolicyLen    uint8
	RuleEnc      [transfer.NRules][ruleEncLen]byte
	InlineAssets [transfer.NInlineAssets]*big.Int
	InlineCount  uint8

	StateRoot     *big.Int
	NullifierRoot *big.Int

	Answers [transfer.NAnswers]Answer
}

type openingJSON struct {
	Domain        string `json:"domain"`
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
	ListId      uint8  `json:"listId"`
	OwnerHash string `json:"ownerHash"`
}

type ruleAnswerJSON struct {
	Enabled           bool     `json:"enabled"`
	Mode              uint8    `json:"mode"`
	ListId              uint8    `json:"listId"`
	State             uint8    `json:"state"`
	AbsentBranch      uint8    `json:"absentBranch"`
	Member            string   `json:"member"`
	ContentHash       string   `json:"contentHash"`
	Version           uint64   `json:"version"`
	Low               string   `json:"low"`
	Next              string   `json:"next"`
	NfPathElements    []string `json:"nfPathElements"`
	NfPathIndex       uint64   `json:"nfPathIndex"`
	StatePathElements []string `json:"statePathElements"`
	StatePathIndex    uint64   `json:"statePathIndex"`
}

type customRingParametersJSON struct {
	CircuitType      string             `json:"circuitType"`
	Variant          string             `json:"variant"`
	PublicInputHash  string             `json:"publicInputHash"`
	PrivateTxHash    string             `json:"privateTxHash"`
	TxViewingSk      string             `json:"txViewingSk"`
	EphSk            string             `json:"ephSk"`
	AuditorPk        string             `json:"auditorPk"`
	NIn              uint8              `json:"nIn"`
	NOut             uint8              `json:"nOut"`
	Inputs           []openingJSON      `json:"inputs"`
	Outputs          []openingJSON      `json:"outputs"`
	AddressChain     string             `json:"addressChain"`
	ExternalDataHash string             `json:"externalDataHash"`
	Sources          []sourceOwnerJSON `json:"sources"`
	PolicyLen        uint8              `json:"policyLen"`
	RuleEnc          []string           `json:"ruleEnc"`
	InlineAssets     []string           `json:"inlineAssets"`
	InlineCount      uint8              `json:"inlineCount"`
	StateRoot        string             `json:"stateRoot"`
	NullifierRoot    string             `json:"nullifierRoot"`
	Answers             []ruleAnswerJSON    `json:"answers"`
}

func (p *CustomRingParameters) MarshalJSON() ([]byte, error) {
	raw := customRingParametersJSON{
		CircuitType:      string(common.CustomRingCircuitType),
		Variant:          TransferVariant,
		PublicInputHash:  common.ToHex(p.PublicInputHash),
		PrivateTxHash:    common.ToHex(p.PrivateTxHash),
		TxViewingSk:      bytesHex(p.TxViewingSk[:]),
		EphSk:            bytesHex(p.EphSk[:]),
		AuditorPk:        bytesHex(p.AuditorPk[:]),
		NIn:              p.NIn,
		NOut:             p.NOut,
		Inputs:           writeOpenings(p.Inputs[:]),
		Outputs:          writeOpenings(p.Outputs[:]),
		AddressChain:     common.ToHex(p.AddressChain),
		ExternalDataHash: common.ToHex(p.ExternalDataHash),
		Sources:          make([]sourceOwnerJSON, 0, len(p.Sources)),
		PolicyLen:        p.PolicyLen,
		RuleEnc:          make([]string, 0, len(p.RuleEnc)),
		InlineAssets:     make([]string, 0, len(p.InlineAssets)),
		InlineCount:      p.InlineCount,
		StateRoot:        common.ToHex(p.StateRoot),
		NullifierRoot:    common.ToHex(p.NullifierRoot),
		Answers:             make([]ruleAnswerJSON, 0, len(p.Answers)),
	}
	for _, src := range p.Sources {
		raw.Sources = append(raw.Sources, sourceOwnerJSON{
			ListId:      src.ListId,
			OwnerHash: common.ToHex(src.OwnerHash),
		})
	}
	for _, encoded := range p.RuleEnc {
		raw.RuleEnc = append(raw.RuleEnc, bytesHex(encoded[:]))
	}
	for _, asset := range p.InlineAssets {
		raw.InlineAssets = append(raw.InlineAssets, common.ToHex(asset))
	}
	for i := range p.Answers {
		raw.Answers = append(raw.Answers, writeAnswer(&p.Answers[i]))
	}
	return json.Marshal(raw)
}

func (p *CustomRingParameters) UnmarshalJSON(data []byte) error {
	var raw customRingParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.CustomRingCircuitType) {
		return fmt.Errorf("custom-ring: unexpected circuitType %q", raw.CircuitType)
	}
	if raw.Variant != TransferVariant {
		return fmt.Errorf("custom-ring: unexpected variant %q", raw.Variant)
	}
	if raw.NIn == 0 || int(raw.NIn) > transfer.NIn {
		return fmt.Errorf("custom-ring: nIn %d is outside 1..%d", raw.NIn, transfer.NIn)
	}
	if raw.NOut == 0 || int(raw.NOut) > transfer.NOut {
		return fmt.Errorf("custom-ring: nOut %d is outside 1..%d", raw.NOut, transfer.NOut)
	}
	if int(raw.PolicyLen) > transfer.NRules {
		return fmt.Errorf("custom-ring: policyLen %d exceeds %d", raw.PolicyLen, transfer.NRules)
	}
	if int(raw.InlineCount) > transfer.NInlineAssets {
		return fmt.Errorf("custom-ring: inlineCount %d exceeds %d", raw.InlineCount, transfer.NInlineAssets)
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
	if p.AddressChain, err = fieldFromHex(raw.AddressChain, "addressChain"); err != nil {
		return err
	}
	if p.ExternalDataHash, err = fieldFromHex(raw.ExternalDataHash, "externalDataHash"); err != nil {
		return err
	}
	if len(raw.Sources) != transfer.NSources {
		return fmt.Errorf("custom-ring: sources holds %d slots, expected %d", len(raw.Sources), transfer.NSources)
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

	p.NIn, p.NOut, p.PolicyLen, p.InlineCount = raw.NIn, raw.NOut, raw.PolicyLen, raw.InlineCount
	if err = readOpenings(p.Inputs[:], raw.Inputs, "inputs"); err != nil {
		return err
	}
	if err = readOpenings(p.Outputs[:], raw.Outputs, "outputs"); err != nil {
		return err
	}
	if len(raw.RuleEnc) != transfer.NRules {
		return fmt.Errorf("custom-ring: ruleEnc holds %d rules, expected %d", len(raw.RuleEnc), transfer.NRules)
	}
	for i, encoded := range raw.RuleEnc {
		if err = bytesFromHex(p.RuleEnc[i][:], encoded, "ruleEnc"); err != nil {
			return err
		}
	}
	if len(raw.InlineAssets) != transfer.NInlineAssets {
		return fmt.Errorf("custom-ring: inlineAssets holds %d entries, expected %d", len(raw.InlineAssets), transfer.NInlineAssets)
	}
	for i, asset := range raw.InlineAssets {
		if p.InlineAssets[i], err = fieldFromHex(asset, "inlineAssets"); err != nil {
			return err
		}
	}
	if len(raw.Answers) != transfer.NAnswers {
		return fmt.Errorf("custom-ring: answers holds %d entries, expected %d", len(raw.Answers), transfer.NAnswers)
	}
	for i, entry := range raw.Answers {
		if err = readPoolEntry(&p.Answers[i], entry); err != nil {
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

func writeAnswer(src *Answer) ruleAnswerJSON {
	return ruleAnswerJSON{
		Enabled:           src.Enabled,
		Mode:              src.Mode,
		ListId:              src.ListId,
		State:             src.State,
		AbsentBranch:      src.AbsentBranch,
		Member:            common.ToHex(src.Member),
		ContentHash:       common.ToHex(src.ContentHash),
		Version:           src.Version,
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

func readPoolEntry(dst *Answer, src ruleAnswerJSON) error {
	if src.Enabled {
		if src.Mode != activeState && src.Mode != clearedState {
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

func (p *CustomRingParameters) CreateWitness() (*transfer.Circuit, error) {
	if p.PublicInputHash == nil || p.PrivateTxHash == nil {
		return nil, fmt.Errorf("custom-ring: missing hash")
	}
	circuit := &transfer.Circuit{
		PublicInputHash:  p.PublicInputHash,
		PrivateTxHash:    p.PrivateTxHash,
		AddressChain:     p.AddressChain,
		ExternalDataHash: p.ExternalDataHash,
		StateRoot:        p.StateRoot,
		NullifierRoot:    p.NullifierRoot,
	}
	for i, src := range p.Sources {
		circuit.Sources[i] = transfer.SourceWires{
			ListId:      src.ListId,
			OwnerHash: src.OwnerHash,
		}
	}
	assignBytes(circuit.TxViewingSk[:], p.TxViewingSk[:])
	assignBytes(circuit.EphSk[:], p.EphSk[:])
	assignBytes(circuit.AuditorPk[:], p.AuditorPk[:])

	for i := range circuit.Inputs {
		assignOpening(&circuit.Inputs[i], &p.Inputs[i])
	}
	for i := range circuit.Outputs {
		assignOpening(&circuit.Outputs[i], &p.Outputs[i])
	}
	assignOneHot(circuit.NInOneHot[:], int(p.NIn)-1)
	assignOneHot(circuit.NOutOneHot[:], int(p.NOut)-1)
	assignOneHot(circuit.LenOneHot[:], int(p.PolicyLen))
	assignOneHot(circuit.InlineCountOneHot[:], int(p.InlineCount))

	for i := range circuit.Rules {
		assignRule(&circuit.Rules[i], p.RuleEnc[i])
	}
	for i := range circuit.InlineAssets {
		circuit.InlineAssets[i] = p.InlineAssets[i]
	}
	for i := range circuit.Answers {
		assignPoolEntry(&circuit.Answers[i], &p.Answers[i])
	}
	return circuit, nil
}

func assignOpening(dst *transfer.OpeningWires, src *Opening) {
	dst.Domain = src.Domain
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

// Byte order mirrors `Rule::encoded`, byte 31 is the subject and bytes 20..28
// the threshold.
func assignRule(dst *transfer.RuleWires, encoded [ruleEncLen]byte) {
	dst.Packed = new(big.Int).SetBytes(encoded[:])
	dst.Subject = encoded[31]
	dst.Mode = encoded[30]
	dst.ListId = encoded[29]
	dst.GuardTag = encoded[28]
	dst.Threshold = new(big.Int).SetBytes(encoded[20:28])
}

func assignPoolEntry(dst *transfer.RuleAnswerWires, src *Answer) {
	dst.Enabled = boolVar(src.Enabled)
	dst.Mode = src.Mode
	dst.ListId = src.ListId
	dst.Member = src.Member
	dst.ContentHash = src.ContentHash
	dst.Version = src.Version
	dst.State = src.State
	dst.AbsentBranch = src.AbsentBranch
	dst.Low = src.Low
	dst.Next = src.Next
	dst.NfPathIndex = src.NfPathIndex
	dst.StatePathIndex = src.StatePathIndex
	for i := range dst.NfPathElements {
		dst.NfPathElements[i] = src.NfPathElements[i]
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
