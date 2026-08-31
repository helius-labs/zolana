package custom_ring

import (
	"bytes"
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/custom_ring/transfer"
)

func sampleParams() *CustomRingParameters {
	p := &CustomRingParameters{
		PublicInputHash:  big.NewInt(0x1234),
		PrivateTxHash:    big.NewInt(0xabcdef),
		NIn:              2,
		NOut:             2,
		AddressChain:     big.NewInt(0x31),
		ExternalDataHash: big.NewInt(0x32),
		PolicyLen:        3,
		InlineCount:      1,
		StateRoot:        big.NewInt(0x34),
		NullifierRoot:    big.NewInt(0x35),
	}
	for i := range p.Sources {
		p.Sources[i] = SourceOwner{ListId: 0, OwnerHash: big.NewInt(0)}
	}
	p.Sources[0] = SourceOwner{ListId: 1, OwnerHash: big.NewInt(0x33)}
	p.Sources[6] = SourceOwner{ListId: 7, OwnerHash: big.NewInt(0x34)}
	for i := range p.TxViewingSk {
		p.TxViewingSk[i] = byte(i)
		p.EphSk[i] = byte(0x20 + i)
	}
	copy(p.AuditorPk[:], elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy))
	for i := range p.Inputs {
		p.Inputs[i] = sampleOpening(int64(0x40 + i))
	}
	for i := range p.Outputs {
		p.Outputs[i] = sampleOpening(int64(0x50 + i))
	}
	for i := range p.RuleEnc {
		for j := range p.RuleEnc[i] {
			p.RuleEnc[i][j] = byte(i ^ j)
		}
	}
	for i := range p.InlineAssets {
		p.InlineAssets[i] = big.NewInt(0)
	}
	p.InlineAssets[0] = big.NewInt(0x60)
	for i := range p.Answers {
		p.Answers[i] = zeroedPoolEntry()
	}
	p.Answers[0].Enabled = true
	p.Answers[0].Mode = activeState
	p.Answers[0].ListId = 1
	p.Answers[0].Member = big.NewInt(0x70)
	p.Answers[0].Version = 3
	return p
}

func sampleOpening(seed int64) Opening {
	return Opening{
		Domain:        big.NewInt(seed),
		OwnerPkHash:   big.NewInt(seed + 1),
		NullifierPk:   big.NewInt(seed + 2),
		Asset:         big.NewInt(seed + 3),
		Amount:        big.NewInt(seed + 4),
		Blinding:      big.NewInt(seed + 5),
		DataHash:      big.NewInt(seed + 6),
		RingDataHash:  big.NewInt(seed + 7),
		RingProgramID: big.NewInt(seed + 8),
	}
}

func zeroedPoolEntry() Answer {
	entry := Answer{
		Member:      big.NewInt(0),
		ContentHash: big.NewInt(0),
		Low:         big.NewInt(0),
		Next:        big.NewInt(0),
	}
	for i := range entry.NfPathElements {
		entry.NfPathElements[i] = big.NewInt(0)
	}
	for i := range entry.StatePathElements {
		entry.StatePathElements[i] = big.NewInt(0)
	}
	return entry
}

func TestCustomRingParametersJSONRoundTrip(t *testing.T) {
	p := sampleParams()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got CustomRingParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	again, err := json.Marshal(&got)
	if err != nil {
		t.Fatalf("marshal again: %v", err)
	}
	if !bytes.Equal(data, again) {
		t.Fatalf("round trip drifted:\n%s\n%s", data, again)
	}
	if got.PublicInputHash.Cmp(p.PublicInputHash) != 0 || got.PrivateTxHash.Cmp(p.PrivateTxHash) != 0 {
		t.Fatalf("hash mismatch")
	}
	if got.TxViewingSk != p.TxViewingSk || got.EphSk != p.EphSk || got.AuditorPk != p.AuditorPk {
		t.Fatalf("byte field mismatch")
	}
	if got.NIn != p.NIn || got.NOut != p.NOut || got.PolicyLen != p.PolicyLen || got.InlineCount != p.InlineCount {
		t.Fatalf("count mismatch")
	}
	if got.RuleEnc != p.RuleEnc {
		t.Fatalf("rule table mismatch")
	}
	for i := range p.Sources {
		if got.Sources[i].ListId != p.Sources[i].ListId ||
			got.Sources[i].OwnerHash.Cmp(p.Sources[i].OwnerHash) != 0 {
			t.Fatalf("source slot %d mismatch", i)
		}
	}
	if !got.Answers[0].Enabled || got.Answers[0].Member.Cmp(p.Answers[0].Member) != 0 {
		t.Fatalf("answer mismatch")
	}
}

func TestCustomRingParametersWireFormat(t *testing.T) {
	data, err := json.Marshal(sampleParams())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	keys := []string{
		"circuitType", "variant", "publicInputHash", "privateTxHash",
		"txViewingSk", "ephSk", "auditorPk", "nIn", "nOut", "inputs",
		"outputs", "addressChain", "externalDataHash", "sources",
		"policyLen", "ruleEnc", "inlineAssets", "inlineCount", "stateRoot",
		"nullifierRoot", "answers",
	}
	if len(raw) != len(keys) {
		t.Fatalf("key set: got %d keys, want %d", len(raw), len(keys))
	}
	for _, key := range keys {
		if _, ok := raw[key]; !ok {
			t.Fatalf("missing key %q", key)
		}
	}
	if got := string(raw["circuitType"]); got != `"custom-ring"` {
		t.Fatalf("circuitType: got %s", got)
	}
	if got := string(raw["variant"]); got != `"transfer"` {
		t.Fatalf("variant: got %s", got)
	}
	for key, length := range map[string]int{
		"publicInputHash": 2 + 2 + 64,
		"txViewingSk":     2 + 2 + 64,
		"auditorPk":       2 + 2 + 130,
	} {
		if got := len(raw[key]); got != length {
			t.Fatalf("%s: got %d chars, want %d", key, got, length)
		}
	}
	for key, count := range map[string]int{
		"inputs":       transfer.NIn,
		"outputs":      transfer.NOut,
		"sources":      transfer.NSources,
		"ruleEnc":      transfer.NRules,
		"inlineAssets": transfer.NInlineAssets,
		"answers":      transfer.NAnswers,
	} {
		var entries []json.RawMessage
		if err := json.Unmarshal(raw[key], &entries); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if len(entries) != count {
			t.Fatalf("%s: got %d entries, want %d", key, len(entries), count)
		}
	}
}

func TestCustomRingParametersRejectBadInput(t *testing.T) {
	base, err := json.Marshal(sampleParams())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	answers := func(m map[string]interface{}) map[string]interface{} {
		return m["answers"].([]interface{})[0].(map[string]interface{})
	}
	source := func(m map[string]interface{}, i int) map[string]interface{} {
		return m["sources"].([]interface{})[i].(map[string]interface{})
	}
	tests := map[string]func(map[string]interface{}){
		"missing circuit type": func(m map[string]interface{}) { delete(m, "circuitType") },
		"foreign circuit type": func(m map[string]interface{}) { m["circuitType"] = "transfer" },
		"foreign variant":      func(m map[string]interface{}) { m["variant"] = "merge" },
		"short scalar":         func(m map[string]interface{}) { m["txViewingSk"] = "0x00" },
		"long auditor pk":      func(m map[string]interface{}) { m["auditorPk"] = m["auditorPk"].(string) + "00" },
		"non hex":              func(m map[string]interface{}) { m["ephSk"] = strings.Repeat("zz", 33) },
		"missing prefix":       func(m map[string]interface{}) { m["ephSk"] = strings.TrimPrefix(m["ephSk"].(string), "0x") },
		"uppercase":            func(m map[string]interface{}) { m["auditorPk"] = strings.ToUpper(m["auditorPk"].(string)) },
		"short field":          func(m map[string]interface{}) { m["privateTxHash"] = "0x01" },
		"zero scalar":          func(m map[string]interface{}) { m["ephSk"] = "0x" + strings.Repeat("00", 32) },
		"scalar at order":      func(m map[string]interface{}) { m["ephSk"] = "0x" + elliptic.P256().Params().N.Text(16) },
		"invalid point":        func(m map[string]interface{}) { m["auditorPk"] = "0x04" + strings.Repeat("00", 64) },
		"hash above field order": func(m map[string]interface{}) {
			m["publicInputHash"] = "0x" + ecc.BN254.ScalarField().Text(16)
		},
		"zero input count":     func(m map[string]interface{}) { m["nIn"] = 0 },
		"input count too high": func(m map[string]interface{}) { m["nIn"] = transfer.NIn + 1 },
		"policy len too high":  func(m map[string]interface{}) { m["policyLen"] = transfer.NRules + 1 },
		"inline count too high": func(m map[string]interface{}) {
			m["inlineCount"] = transfer.NInlineAssets + 1
		},
		"nonzero inline padding": func(m map[string]interface{}) {
			m["inlineAssets"].([]interface{})[1] = "0x01" + strings.Repeat("00", 31)
		},
		"missing input slot": func(m map[string]interface{}) { m["inputs"] = m["inputs"].([]interface{})[:1] },
		"missing rule":       func(m map[string]interface{}) { m["ruleEnc"] = m["ruleEnc"].([]interface{})[:transfer.NRules-1] },
		"missing answer":     func(m map[string]interface{}) { m["answers"] = m["answers"].([]interface{})[:transfer.NAnswers-1] },
		"short sources": func(m map[string]interface{}) {
			m["sources"] = m["sources"].([]interface{})[:transfer.NSources-1]
		},
		"source listId at wrong position": func(m map[string]interface{}) {
			source(m, 1)["listId"] = 1
			source(m, 1)["ownerHash"] = source(m, 0)["ownerHash"]
		},
		"empty source slot with nonzero owner": func(m map[string]interface{}) {
			source(m, 2)["ownerHash"] = source(m, 0)["ownerHash"]
		},
		"answers mode invalid": func(m map[string]interface{}) { answers(m)["mode"] = 9 },
		"answers listId unset": func(m map[string]interface{}) { answers(m)["listId"] = 0 },
		"zero answers member":  func(m map[string]interface{}) { answers(m)["member"] = "0x" + strings.Repeat("00", 32) },
		"short nullifier path": func(m map[string]interface{}) {
			paths := answers(m)["nfPathElements"].([]interface{})
			answers(m)["nfPathElements"] = paths[:len(paths)-1]
		},
	}
	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			var raw map[string]interface{}
			if err := json.Unmarshal(base, &raw); err != nil {
				t.Fatalf("unmarshal raw: %v", err)
			}
			tamper(raw)
			data, err := json.Marshal(raw)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got CustomRingParameters
			if err := json.Unmarshal(data, &got); err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}

func TestCustomRingParametersCreateWitness(t *testing.T) {
	assignment, err := sampleParams().CreateWitness()
	if err != nil {
		t.Fatalf("create assignment: %v", err)
	}
	if _, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("create gnark witness: %v", err)
	}
}
