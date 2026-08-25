package custom_ring

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/circuits/spp_transaction/shared"
)

const (
	ruleEncLen   = 32
	activeState  = 1
	clearedState = 2
)

// PolicyOpening is one UTXO slot the statement opens, ordered as the circuit
// hashes it.
type PolicyOpening struct {
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

// PolicyPoolEntry is one record fact the statement proves against the roots.
type PolicyPoolEntry struct {
	Enabled      bool
	Mode         uint8
	Kind         uint8
	State        uint8
	AbsentBranch uint8
	Member       *big.Int
	PayloadHash  *big.Int
	Version      uint64
	Low          *big.Int
	Next         *big.Int

	NfPathElements [shared.NullifierTreeHeight]*big.Int
	NfPathIndex    uint64

	StatePathElements [shared.StateTreeHeight]*big.Int
	StatePathIndex    uint64
}

type CustomRingPolicyParameters struct {
	PublicInputHash *big.Int
	PrivateTxHash   *big.Int
	TxViewingSk     [scalarLen]byte
	EphSk           [scalarLen]byte
	AuditorPk       [uncompressedPubkeyLen]byte

	NIn     uint8
	NOut    uint8
	Inputs  [policy.NIn]PolicyOpening
	Outputs [policy.NOut]PolicyOpening

	AddressChain     *big.Int
	ExternalDataHash *big.Int

	RecordsOwnerHash *big.Int
	PolicyLen        uint8
	RuleEnc          [policy.NRules][ruleEncLen]byte
	InlineAssets     [policy.NInlineAssets]*big.Int
	InlineCount      uint8

	StateRoot     *big.Int
	NullifierRoot *big.Int

	Pool [policy.NPool]PolicyPoolEntry
}

type policyOpeningJSON struct {
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

type policyPoolEntryJSON struct {
	Enabled           bool     `json:"enabled"`
	Mode              uint8    `json:"mode"`
	Kind              uint8    `json:"kind"`
	State             uint8    `json:"state"`
	AbsentBranch      uint8    `json:"absentBranch"`
	Member            string   `json:"member"`
	PayloadHash       string   `json:"payloadHash"`
	Version           uint64   `json:"version"`
	Low               string   `json:"low"`
	Next              string   `json:"next"`
	NfPathElements    []string `json:"nfPathElements"`
	NfPathIndex       uint64   `json:"nfPathIndex"`
	StatePathElements []string `json:"statePathElements"`
	StatePathIndex    uint64   `json:"statePathIndex"`
}

type customRingPolicyParametersJSON struct {
	CircuitType      string                `json:"circuitType"`
	Variant          string                `json:"variant"`
	PublicInputHash  string                `json:"publicInputHash"`
	PrivateTxHash    string                `json:"privateTxHash"`
	TxViewingSk      string                `json:"txViewingSk"`
	EphSk            string                `json:"ephSk"`
	AuditorPk        string                `json:"auditorPk"`
	NIn              uint8                 `json:"nIn"`
	NOut             uint8                 `json:"nOut"`
	Inputs           []policyOpeningJSON   `json:"inputs"`
	Outputs          []policyOpeningJSON   `json:"outputs"`
	AddressChain     string                `json:"addressChain"`
	ExternalDataHash string                `json:"externalDataHash"`
	RecordsOwnerHash string                `json:"recordsOwnerHash"`
	PolicyLen        uint8                 `json:"policyLen"`
	RuleEnc          []string              `json:"ruleEnc"`
	InlineAssets     []string              `json:"inlineAssets"`
	InlineCount      uint8                 `json:"inlineCount"`
	StateRoot        string                `json:"stateRoot"`
	NullifierRoot    string                `json:"nullifierRoot"`
	Pool             []policyPoolEntryJSON `json:"pool"`
}

func (p *CustomRingPolicyParameters) UnmarshalJSON(data []byte) error {
	var raw customRingPolicyParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(policyCircuitType) {
		return fmt.Errorf("custom-ring-policy: unexpected circuitType %q", raw.CircuitType)
	}
	if raw.Variant != TransferVariant {
		return fmt.Errorf("custom-ring-policy: unexpected variant %q", raw.Variant)
	}
	if raw.NIn == 0 || int(raw.NIn) > policy.NIn {
		return fmt.Errorf("custom-ring-policy: nIn %d is outside 1..%d", raw.NIn, policy.NIn)
	}
	if raw.NOut == 0 || int(raw.NOut) > policy.NOut {
		return fmt.Errorf("custom-ring-policy: nOut %d is outside 1..%d", raw.NOut, policy.NOut)
	}
	if int(raw.PolicyLen) > policy.NRules {
		return fmt.Errorf("custom-ring-policy: policyLen %d exceeds %d", raw.PolicyLen, policy.NRules)
	}
	if int(raw.InlineCount) > policy.NInlineAssets {
		return fmt.Errorf("custom-ring-policy: inlineCount %d exceeds %d", raw.InlineCount, policy.NInlineAssets)
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
		return fmt.Errorf("custom-ring-policy: auditorPk is not a P256 point")
	}
	if p.AddressChain, err = fieldFromHex(raw.AddressChain, "addressChain"); err != nil {
		return err
	}
	if p.ExternalDataHash, err = fieldFromHex(raw.ExternalDataHash, "externalDataHash"); err != nil {
		return err
	}
	if p.RecordsOwnerHash, err = fieldFromHex(raw.RecordsOwnerHash, "recordsOwnerHash"); err != nil {
		return err
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
	if len(raw.RuleEnc) != policy.NRules {
		return fmt.Errorf("custom-ring-policy: ruleEnc holds %d rules, expected %d", len(raw.RuleEnc), policy.NRules)
	}
	for i, encoded := range raw.RuleEnc {
		if err = bytesFromHex(p.RuleEnc[i][:], encoded, "ruleEnc"); err != nil {
			return err
		}
	}
	if len(raw.InlineAssets) != policy.NInlineAssets {
		return fmt.Errorf("custom-ring-policy: inlineAssets holds %d entries, expected %d", len(raw.InlineAssets), policy.NInlineAssets)
	}
	for i, asset := range raw.InlineAssets {
		if p.InlineAssets[i], err = fieldFromHex(asset, "inlineAssets"); err != nil {
			return err
		}
	}
	if len(raw.Pool) != policy.NPool {
		return fmt.Errorf("custom-ring-policy: pool holds %d entries, expected %d", len(raw.Pool), policy.NPool)
	}
	for i, entry := range raw.Pool {
		if err = readPoolEntry(&p.Pool[i], entry); err != nil {
			return err
		}
	}
	return nil
}

func readOpenings(dst []PolicyOpening, src []policyOpeningJSON, name string) error {
	if len(src) != len(dst) {
		return fmt.Errorf("custom-ring-policy: %s holds %d slots, expected %d", name, len(src), len(dst))
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

func readPoolEntry(dst *PolicyPoolEntry, src policyPoolEntryJSON) error {
	if src.Enabled {
		if src.Mode != activeState && src.Mode != clearedState {
			return fmt.Errorf("custom-ring-policy: pool mode %d is not present or absent", src.Mode)
		}
		if src.Kind == 0 {
			return fmt.Errorf("custom-ring-policy: pool kind is unset")
		}
	}
	dst.Enabled = src.Enabled
	dst.Mode, dst.Kind, dst.State, dst.AbsentBranch = src.Mode, src.Kind, src.State, src.AbsentBranch
	dst.Version, dst.NfPathIndex, dst.StatePathIndex = src.Version, src.NfPathIndex, src.StatePathIndex

	var err error
	if dst.Member, err = fieldFromHex(src.Member, "member"); err != nil {
		return err
	}
	if src.Enabled && dst.Member.Sign() == 0 {
		return fmt.Errorf("custom-ring-policy: pool member is zero")
	}
	if dst.PayloadHash, err = fieldFromHex(src.PayloadHash, "payloadHash"); err != nil {
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
		return fmt.Errorf("custom-ring-policy: %s holds %d nodes, expected %d", name, len(src), len(dst))
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

func (p *CustomRingPolicyParameters) CreateWitness() (*policy.Circuit, error) {
	if p.PublicInputHash == nil || p.PrivateTxHash == nil {
		return nil, fmt.Errorf("custom-ring-policy: missing hash")
	}
	circuit := &policy.Circuit{
		PublicInputHash:  p.PublicInputHash,
		PrivateTxHash:    p.PrivateTxHash,
		AddressChain:     p.AddressChain,
		ExternalDataHash: p.ExternalDataHash,
		RecordsOwnerHash: p.RecordsOwnerHash,
		StateRoot:        p.StateRoot,
		NullifierRoot:    p.NullifierRoot,
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
	for i := range circuit.Pool {
		assignPoolEntry(&circuit.Pool[i], &p.Pool[i])
	}
	return circuit, nil
}

func assignOpening(dst *policy.OpeningWires, src *PolicyOpening) {
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
func assignRule(dst *policy.RuleWires, encoded [ruleEncLen]byte) {
	dst.Packed = new(big.Int).SetBytes(encoded[:])
	dst.Subject = encoded[31]
	dst.Mode = encoded[30]
	dst.Kind = encoded[29]
	dst.GuardTag = encoded[28]
	dst.Threshold = new(big.Int).SetBytes(encoded[20:28])
}

func assignPoolEntry(dst *policy.PoolEntryWires, src *PolicyPoolEntry) {
	dst.Enabled = boolVar(src.Enabled)
	dst.Mode = src.Mode
	dst.Kind = src.Kind
	dst.Member = src.Member
	dst.PayloadHash = src.PayloadHash
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
