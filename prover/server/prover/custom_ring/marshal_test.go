package custom_ring

import (
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func sampleParams() *CustomRingParameters {
	p := &CustomRingParameters{
		PublicInputHash: big.NewInt(0x1234),
		PrivateTxHash:   big.NewInt(0xabcdef),
	}
	for i := range p.TxViewingSk {
		p.TxViewingSk[i] = byte(i)
		p.EphSk[i] = byte(0x20 + i)
	}
	copy(p.AuditorPk[:], elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy))
	return p
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
	if got.PublicInputHash.Cmp(p.PublicInputHash) != 0 || got.PrivateTxHash.Cmp(p.PrivateTxHash) != 0 {
		t.Fatalf("hash mismatch")
	}
	if got.TxViewingSk != p.TxViewingSk || got.EphSk != p.EphSk || got.AuditorPk != p.AuditorPk {
		t.Fatalf("byte field mismatch")
	}
}

func TestCustomRingParametersWireFormat(t *testing.T) {
	data, err := json.Marshal(sampleParams())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	want := map[string]int{
		"circuitType":     len("custom-ring"),
		"variant":         len(TransferVariant),
		"publicInputHash": 2 + 64,
		"privateTxHash":   2 + 64,
		"txViewingSk":     2 + 64,
		"ephSk":           2 + 64,
		"auditorPk":       2 + 130,
	}
	if len(raw) != len(want) {
		t.Fatalf("key set: got %v", raw)
	}
	for key, length := range want {
		if got := len(raw[key]); got != length {
			t.Fatalf("%s: got %d chars, want %d", key, got, length)
		}
	}
}

func TestCustomRingParametersRejectBadInput(t *testing.T) {
	base, err := json.Marshal(sampleParams())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tests := map[string]func(map[string]string){
		"missing circuit type": func(m map[string]string) { delete(m, "circuitType") },
		"foreign circuit type": func(m map[string]string) { m["circuitType"] = "transfer" },
		"short scalar":         func(m map[string]string) { m["txViewingSk"] = "0x00" },
		"long auditor pk":      func(m map[string]string) { m["auditorPk"] = m["auditorPk"] + "00" },
		"non hex":              func(m map[string]string) { m["ephSk"] = strings.Repeat("zz", 32) },
		"missing prefix":       func(m map[string]string) { m["ephSk"] = strings.TrimPrefix(m["ephSk"], "0x") },
		"uppercase":            func(m map[string]string) { m["auditorPk"] = strings.ToUpper(m["auditorPk"]) },
		"short field":          func(m map[string]string) { m["privateTxHash"] = "0x01" },
		"zero scalar":          func(m map[string]string) { m["ephSk"] = "0x" + strings.Repeat("00", 32) },
		"scalar at order":      func(m map[string]string) { m["ephSk"] = "0x" + elliptic.P256().Params().N.Text(16) },
		"invalid point":        func(m map[string]string) { m["auditorPk"] = "0x04" + strings.Repeat("00", 64) },
		"hash above field order": func(m map[string]string) {
			m["publicInputHash"] = "0x" + ecc.BN254.ScalarField().Text(16)
		},
	}
	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			var raw map[string]string
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
