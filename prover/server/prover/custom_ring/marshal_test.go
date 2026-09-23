package custom_ring

import (
	"bytes"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/circuits/verifiable-encryption/p256"
	"zolana/prover/custom_rings/circuits/policy"
	"zolana/prover/custom_rings/circuits/registry"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"
)

func sampleBaseParams() *BaseParameters {
	p := &BaseParameters{
		PublicInputHash: big.NewInt(0x1234),
		PrivateTxHash:   big.NewInt(0xabcdef),
		NOut:            1,
	}
	for i := range p.TxViewingSk {
		p.TxViewingSk[i] = byte(i)
		p.EphSk[i] = byte(0x20 + i)
	}
	copy(p.AuditorPk[:], elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy))
	for i := range p.Outputs {
		p.Outputs[i] = zeroedAuditOpening()
	}
	return p
}

func sampleParams() *PolicyParameters {
	base := sampleBaseParams()
	p := &PolicyParameters{
		PublicInputHash:    base.PublicInputHash,
		PrivateTxHash:      base.PrivateTxHash,
		TxViewingSk:        base.TxViewingSk,
		EphSk:              base.EphSk,
		AuditorPk:          base.AuditorPk,
		NIn:                2,
		NOut:               2,
		AddressChain:       big.NewInt(0x31),
		ExternalDataHash:   big.NewInt(0x32),
		PrivateTxBlinding:  big.NewInt(0x36),
		PolicyLen:          3,
		InlineCount:        1,
		WindowSlots:        216000,
		VelocityCount:      1,
		AddressTreeID:      big.NewInt(0x37),
		KeyEscrow:          KeyEscrow{Enabled: true, Root: big.NewInt(0x3d)},
		RingID:             big.NewInt(0x38),
		NamespaceOwnerHash: big.NewInt(0x39),
		WindowIndex:        4,
		ApprovalRequired:   true,
		Record:             zeroedRecord(),
	}
	p.Record.Version = 2
	p.Record.Window = 3
	p.Record.Commitment = big.NewInt(0x3a)
	p.Record.Salt = big.NewInt(0x3b)
	p.Record.NextSalt = big.NewInt(0x3c)
	p.Record.Assets[0] = big.NewInt(0x61)
	p.Record.Spent[0] = big.NewInt(500)
	p.TreeSlots = zeroedTreeSlots()
	p.TreeSlots[0] = TreeSlot{ID: big.NewInt(0x37), UtxoRoot: big.NewInt(0x34), NullifierRoot: big.NewInt(0x35)}
	p.TreeSlots[1] = TreeSlot{ID: big.NewInt(0x3e), UtxoRoot: big.NewInt(0x3f), NullifierRoot: big.NewInt(0x41)}
	for i := range p.Sources {
		p.Sources[i] = SourceOwner{ListId: 0, OwnerHash: big.NewInt(0)}
	}
	for i := range p.Velocity {
		p.Velocity[i] = VelocityRow{Asset: big.NewInt(0), Cap: big.NewInt(0), CosignAbove: big.NewInt(0)}
	}
	p.Velocity[0] = VelocityRow{Asset: big.NewInt(0x61), Cap: big.NewInt(1000), CosignAbove: big.NewInt(600)}
	p.Sources[0] = SourceOwner{ListId: 1, OwnerHash: big.NewInt(0x33)}
	p.Sources[6] = SourceOwner{ListId: 7, OwnerHash: big.NewInt(0x34)}
	for i := range p.Inputs {
		p.Inputs[i] = sampleOpening(int64(0x40 + i))
	}
	for i := range p.Outputs {
		p.Outputs[i] = sampleOpening(int64(0x50 + i))
	}
	p.Outputs[0].Key = &RegistryKey{Next: big.NewInt(0x5a), CtHash: big.NewInt(0x5b), Index: 3}
	for i := range p.Outputs[0].Key.Path {
		p.Outputs[0].Key.Path[i] = big.NewInt(int64(0x100 + i))
	}
	for i := range p.RuleEnc {
		for j := range p.RuleEnc[i] {
			p.RuleEnc[i][j] = byte(i ^ j)
		}
	}
	for i := range p.InlineAssets {
		p.InlineAssets[i] = big.NewInt(0)
		p.InlineLimits[i] = big.NewInt(0)
	}
	p.InlineAssets[0] = big.NewInt(0x60)
	for i := range p.ListFacts {
		p.ListFacts[i] = zeroedListFact()
	}
	p.ListFacts[0].Enabled = true
	p.ListFacts[0].Mode = policy.ModePresent
	p.ListFacts[0].ListId = 1
	p.ListFacts[0].Member = big.NewInt(0x70)
	p.ListFacts[0].Version = 3
	p.ListFacts[0].TreeSlot = 1
	return p
}

func zeroedTreeSlots() [shared.InputTrees]TreeSlot {
	var slots [shared.InputTrees]TreeSlot
	for i := range slots {
		slots[i] = TreeSlot{ID: big.NewInt(0), UtxoRoot: big.NewInt(0), NullifierRoot: big.NewInt(0)}
	}
	return slots
}

func sampleOpening(seed int64) Opening {
	return Opening{
		Domain:        big.NewInt(seed),
		TreeID:        big.NewInt(seed + 9),
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

func zeroedListFact() ListFact {
	fact := ListFact{
		Member:      big.NewInt(0),
		ContentHash: big.NewInt(0),
		Blinding:    big.NewInt(0),
		Low:         big.NewInt(0),
		Next:        big.NewInt(0),
	}
	for i := range fact.NfPathElements {
		fact.NfPathElements[i] = big.NewInt(0)
	}
	for i := range fact.StatePathElements {
		fact.StatePathElements[i] = big.NewInt(0)
	}
	return fact
}

func TestPolicyParametersJSONRoundTrip(t *testing.T) {
	p := sampleParams()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got PolicyParameters
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
	if got.WindowSlots != p.WindowSlots || got.VelocityCount != p.VelocityCount ||
		got.WindowIndex != p.WindowIndex || got.ApprovalRequired != p.ApprovalRequired {
		t.Fatalf("velocity scalar mismatch")
	}
	if got.Velocity[0].Cap.Cmp(p.Velocity[0].Cap) != 0 || got.Velocity[0].CosignAbove.Cmp(p.Velocity[0].CosignAbove) != 0 {
		t.Fatalf("velocity row mismatch")
	}
	if got.Record.Version != p.Record.Version || got.Record.Commitment.Cmp(p.Record.Commitment) != 0 ||
		got.Record.Spent[0].Cmp(p.Record.Spent[0]) != 0 || got.RingID.Cmp(p.RingID) != 0 {
		t.Fatalf("record mismatch")
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
	if !got.ListFacts[0].Enabled || got.ListFacts[0].Member.Cmp(p.ListFacts[0].Member) != 0 || got.ListFacts[0].TreeSlot != 1 {
		t.Fatalf("list fact mismatch")
	}
	if got.TreeSlots[1].NullifierRoot.Cmp(p.TreeSlots[1].NullifierRoot) != 0 || got.TreeSlots[2].ID.Sign() != 0 {
		t.Fatalf("tree slots mismatch")
	}
	if !got.KeyEscrow.Enabled || got.Outputs[0].Key.Path[39].Cmp(p.Outputs[0].Key.Path[39]) != 0 || got.Outputs[1].Key != nil {
		t.Fatalf("key escrow mismatch")
	}
}

func TestPolicyParametersWireFormat(t *testing.T) {
	data, err := json.Marshal(sampleParams())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	keys := []string{
		"circuitType", "publicInputHash", "privateTxHash",
		"txViewingSk", "ephSk", "auditorPk", "salt", "nIn", "nOut", "inputs",
		"outputs", "addressChain", "externalDataHash", "privateTxBlinding", "sources",
		"policyLen", "ruleEnc", "inlineAssets", "inlineLimits", "inlineCount", "treeSlots", "addressTreeId",
		"keyEscrow", "keyRegistryRoot", "answers", "windowSlots", "velocity", "velocityCount", "ringId",
		"namespaceOwnerHash", "windowIndex", "approvalRequired", "record",
	}
	if len(raw) != len(keys) {
		t.Fatalf("key set: got %d keys, want %d", len(raw), len(keys))
	}
	for _, key := range keys {
		if _, ok := raw[key]; !ok {
			t.Fatalf("missing key %q", key)
		}
	}
	if got := string(raw["circuitType"]); got != `"custom-ring-policy"` {
		t.Fatalf("circuitType: got %s", got)
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
		"inputs":       policy.NInputs,
		"outputs":      policy.NOutputs,
		"sources":      policy.NSources,
		"ruleEnc":      policy.NRules,
		"inlineAssets": policy.NInlineAssets,
		"inlineLimits": policy.NInlineAssets,
		"answers":      policy.NListFacts,
		"velocity":     policy.NVelocityAssets,
		"treeSlots":    2,
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

func TestPolicyParametersRejectBadInput(t *testing.T) {
	base, err := json.Marshal(sampleParams())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	listFacts := func(m map[string]interface{}) map[string]interface{} {
		return m["answers"].([]interface{})[0].(map[string]interface{})
	}
	source := func(m map[string]interface{}, i int) map[string]interface{} {
		return m["sources"].([]interface{})[i].(map[string]interface{})
	}
	slot := func(m map[string]interface{}, key string, i int) map[string]interface{} {
		return m[key].([]interface{})[i].(map[string]interface{})
	}
	tests := map[string]func(map[string]interface{}){
		"missing circuit type": func(m map[string]interface{}) { delete(m, "circuitType") },
		"foreign circuit type": func(m map[string]interface{}) { m["circuitType"] = "transfer" },
		"short scalar":         func(m map[string]interface{}) { m["txViewingSk"] = "0x00" },
		"long auditor pk":      func(m map[string]interface{}) { m["auditorPk"] = m["auditorPk"].(string) + "00" },
		"non hex":              func(m map[string]interface{}) { m["ephSk"] = strings.Repeat("zz", 33) },
		"missing prefix":       func(m map[string]interface{}) { m["ephSk"] = strings.TrimPrefix(m["ephSk"].(string), "0x") },
		"uppercase":            func(m map[string]interface{}) { m["auditorPk"] = strings.ToUpper(m["auditorPk"].(string)) },
		"short field":          func(m map[string]interface{}) { m["privateTxHash"] = "0x01" },
		"zero scalar":          func(m map[string]interface{}) { m["ephSk"] = zeroScalarHex },
		"scalar at order":      func(m map[string]interface{}) { m["ephSk"] = orderScalarHex() },
		"zero tx scalar":       func(m map[string]interface{}) { m["txViewingSk"] = zeroScalarHex },
		"tx scalar at order":   func(m map[string]interface{}) { m["txViewingSk"] = orderScalarHex() },
		"invalid point":        func(m map[string]interface{}) { m["auditorPk"] = "0x04" + strings.Repeat("00", 64) },
		"hash above field order": func(m map[string]interface{}) {
			m["publicInputHash"] = "0x" + ecc.BN254.ScalarField().Text(16)
		},
		"zero input count":     func(m map[string]interface{}) { m["nIn"] = 0 },
		"input count too high": func(m map[string]interface{}) { m["nIn"] = policy.NInputs + 1 },
		"policy len too high":  func(m map[string]interface{}) { m["policyLen"] = policy.NRules + 1 },
		"inline count too high": func(m map[string]interface{}) {
			m["inlineCount"] = policy.NInlineAssets + 1
		},
		"nonzero inline padding": func(m map[string]interface{}) {
			m["inlineAssets"].([]interface{})[1] = "0x01" + strings.Repeat("00", 31)
		},
		"missing input slot": func(m map[string]interface{}) { m["inputs"] = m["inputs"].([]interface{})[:1] },
		"missing rule":       func(m map[string]interface{}) { m["ruleEnc"] = m["ruleEnc"].([]interface{})[:policy.NRules-1] },
		"missing answer":     func(m map[string]interface{}) { m["answers"] = m["answers"].([]interface{})[:policy.NListFacts-1] },
		"short sources": func(m map[string]interface{}) {
			m["sources"] = m["sources"].([]interface{})[:policy.NSources-1]
		},
		"source listId at wrong position": func(m map[string]interface{}) {
			source(m, 1)["listId"] = 1
			source(m, 1)["ownerHash"] = source(m, 0)["ownerHash"]
		},
		"empty source slot with nonzero owner": func(m map[string]interface{}) {
			source(m, 2)["ownerHash"] = source(m, 0)["ownerHash"]
		},
		"answers mode invalid": func(m map[string]interface{}) { listFacts(m)["mode"] = 9 },
		"answers listId unset": func(m map[string]interface{}) { listFacts(m)["listId"] = 0 },
		"zero answers member":  func(m map[string]interface{}) { listFacts(m)["member"] = "0x" + strings.Repeat("00", 32) },
		"short nullifier path": func(m map[string]interface{}) {
			paths := listFacts(m)["nfPathElements"].([]interface{})
			listFacts(m)["nfPathElements"] = paths[:len(paths)-1]
		},
		"velocity count too high": func(m map[string]interface{}) {
			m["velocityCount"] = policy.NVelocityAssets + 1
		},
		"a window without velocity rows": func(m map[string]interface{}) { m["velocityCount"] = 0 },
		"nonzero velocity padding": func(m map[string]interface{}) {
			m["velocity"].([]interface{})[1].(map[string]interface{})["cap"] = "0x" + strings.Repeat("00", 31) + "01"
		},
		"velocity cap above 64 bits": func(m map[string]interface{}) {
			m["velocity"].([]interface{})[0].(map[string]interface{})["cap"] = "0x" + strings.Repeat("00", 23) + "01" + strings.Repeat("00", 8)
		},
		"short velocity": func(m map[string]interface{}) {
			m["velocity"] = m["velocity"].([]interface{})[:policy.NVelocityAssets-1]
		},
		"short record counters": func(m map[string]interface{}) {
			record := m["record"].(map[string]interface{})
			record["spent"] = record["spent"].([]interface{})[:policy.NVelocityAssets-1]
		},
		"no tree slots": func(m map[string]interface{}) { m["treeSlots"] = []interface{}{} },
		"six tree slots": func(m map[string]interface{}) {
			slots := m["treeSlots"].([]interface{})
			m["treeSlots"] = append(slots, slots[0], slots[0], slots[0], slots[0])
		},
		"tree slot with a zero root": func(m map[string]interface{}) { slot(m, "treeSlots", 1)["utxoRoot"] = zeroScalarHex },
		"tree slot id above 16 bits": func(m map[string]interface{}) {
			slot(m, "treeSlots", 1)["id"] = "0x" + strings.Repeat("00", 29) + "010000"
		},
		"answer in an unpopulated slot": func(m map[string]interface{}) { listFacts(m)["treeSlot"] = 2 },
		"registry root with escrow off": func(m map[string]interface{}) { m["keyEscrow"] = false },
		"key on an input":               func(m map[string]interface{}) { slot(m, "inputs", 0)["key"] = slot(m, "outputs", 0)["key"] },
		"key index above 40 bits": func(m map[string]interface{}) {
			slot(m, "outputs", 0)["key"].(map[string]interface{})["index"] = uint64(1) << 40
		},
		"short key path": func(m map[string]interface{}) {
			key := slot(m, "outputs", 0)["key"].(map[string]interface{})
			key["path"] = key["path"].([]interface{})[:39]
		},
		"unescrowed utxo output": func(m map[string]interface{}) {
			slot(m, "outputs", 1)["domain"] = common.ToHex(big.NewInt(shared.UtxoDomain))
		},
		"record counter above 64 bits": func(m map[string]interface{}) {
			record := m["record"].(map[string]interface{})
			record["spent"].([]interface{})[0] = "0x" + strings.Repeat("00", 23) + "01" + strings.Repeat("00", 8)
		},
	}
	rejectTampered[PolicyParameters](t, base, tests)
}

func TestBaseParametersRejectBadInput(t *testing.T) {
	base, err := json.Marshal(sampleBaseParams())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tests := map[string]func(map[string]interface{}){
		"foreign circuit type": func(m map[string]interface{}) { m["circuitType"] = "transfer" },
		"zero tx scalar":       func(m map[string]interface{}) { m["txViewingSk"] = zeroScalarHex },
		"tx scalar at order":   func(m map[string]interface{}) { m["txViewingSk"] = orderScalarHex() },
		"zero eph scalar":      func(m map[string]interface{}) { m["ephSk"] = zeroScalarHex },
		"eph scalar at order":  func(m map[string]interface{}) { m["ephSk"] = orderScalarHex() },
		"invalid point":        func(m map[string]interface{}) { m["auditorPk"] = "0x04" + strings.Repeat("00", 64) },
		"short field":          func(m map[string]interface{}) { m["privateTxHash"] = "0x01" },
	}
	rejectTampered[BaseParameters](t, base, tests)
}

const zeroScalarHex = "0x0000000000000000000000000000000000000000000000000000000000000000"

func orderScalarHex() string {
	return "0x" + p256.GroupOrder().Text(16)
}

func rejectTampered[P any](t *testing.T, base []byte, tests map[string]func(map[string]interface{})) {
	t.Helper()
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
			var got P
			if err := json.Unmarshal(data, &got); err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}

// A per-transfer cap carries rows with no window, WindowSlots zero.
func TestPolicyParametersAcceptRowsWithoutAWindow(t *testing.T) {
	p := sampleParams()
	p.WindowSlots = 0
	p.WindowIndex = 0
	p.Record = zeroedRecord()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got PolicyParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("rows without a window are a per-transfer cap: %v", err)
	}
}

// Only the namespace record may carry the zero key without a registration.
func TestPolicyParametersExemptOnlyTheNamespaceRecord(t *testing.T) {
	p := sampleParams()
	output := &p.Outputs[1]
	output.Domain, output.NullifierPk = big.NewInt(shared.UtxoDomain), registry.ZeroNullifierPk
	decode := func() error {
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return json.Unmarshal(data, &PolicyParameters{})
	}
	if err := decode(); err == nil || !strings.Contains(err.Error(), "zero key without the namespace owner") {
		t.Fatalf("member zero key admitted: %v", err)
	}
	p.NamespaceOwnerHash = spptest.MustOwnerHash(t, output.OwnerPkHash, output.NullifierPk)
	if err := decode(); err != nil {
		t.Fatalf("namespace record refused: %v", err)
	}
}

func TestPolicyParametersRefuseAMissingTreeRoot(t *testing.T) {
	p := sampleParams()
	p.TreeSlots[2].UtxoRoot = nil
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("a nil tree root was encoded")
	}
}

func TestPolicyParametersCreateWitness(t *testing.T) {
	assignment, err := sampleParams().CreateWitness()
	if err != nil {
		t.Fatalf("create assignment: %v", err)
	}
	if _, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("create gnark witness: %v", err)
	}
}

func TestAssignRuleReadsTheEncodedBytes(t *testing.T) {
	var encoded [ruleEncLen]byte
	for i := range encoded {
		encoded[i] = byte(i)
	}
	var wires policy.RuleWires
	assignRule(&wires, encoded)
	for name, check := range map[string]struct{ got, want string }{
		"subject":   {fmt.Sprint(wires.Subject), "31"},
		"mode":      {fmt.Sprint(wires.Mode), "30"},
		"mask":      {fmt.Sprint(wires.ListMask), "29"},
		"guardTag":  {fmt.Sprint(wires.GuardTag), "28"},
		"threshold": {wires.Threshold.(*big.Int).Text(16), "1415161718191a1b"},
		"altMask":   {fmt.Sprint(wires.OppositeModeListMask), "19"},
	} {
		if check.got != check.want {
			t.Errorf("%s: got %s, want %s", name, check.got, check.want)
		}
	}
}
