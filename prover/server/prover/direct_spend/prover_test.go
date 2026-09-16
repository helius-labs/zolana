package directspend

import (
	"encoding/json"
	"strings"
	"testing"

	"zolana/prover/prover/common"
)

func TestDecodeRejectsMalformedWitness(t *testing.T) {
	zero := "0x" + strings.Repeat("0", 64)
	value := map[string]any{"ID": zero, "Commitment": zero, "Amount": zero, "Randomness": zero}
	output := map[string]any{"OwnerKey": zero, "NullifierPK": zero, "Amount": zero, "Blinding": zero, "Hash": zero}
	valid := map[string]any{"Intent": zero, "OutputTreeID": zero, "Asset": zero, "Values": []any{value}, "Outputs": []any{output}, "PublicInputHash": zero}
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing field", func(v map[string]any) { delete(v, "Asset") }},
		{"float field", func(v map[string]any) { v["Asset"] = 1 }},
		{"oversized field", func(v map[string]any) { v["Asset"] = "0x" + strings.Repeat("f", 64) }},
		{"extra field", func(v map[string]any) { v["unknown"] = zero }},
		{"wrong shape", func(v map[string]any) { v["Values"] = []any{value, value} }},
		{"null slice", func(v map[string]any) { v["Outputs"] = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := map[string]any{}
			for k, value := range valid {
				v[k] = value
			}
			tc.mutate(v)
			witness, _ := json.Marshal(v)
			body, _ := json.Marshal(Request{CircuitType: common.SpendBalanceCircuitType, NInputs: 1, NOutputs: 1, Witness: witness})
			if _, _, err := Decode(body); err == nil {
				t.Fatal("accepted malformed witness")
			}
		})
	}
	witness, _ := json.Marshal(valid)
	body, _ := json.Marshal(Request{CircuitType: common.SpendBalanceCircuitType, NInputs: 1, NOutputs: 1, Witness: witness})
	if _, _, err := Decode(body); err != nil {
		t.Fatal(err)
	}
}
