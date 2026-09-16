package directspend

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	direct "zolana/prover/circuits/direct_spend"
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

func TestPaymentCircuitSelection(t *testing.T) {
	for _, kind := range []common.CircuitType{common.DirectPaymentGKRCircuitType, common.DirectPaymentAdmittedCircuitType, common.DirectPaymentAdmittedDAG10CircuitType} {
		for _, inputs := range []uint32{144, 512} {
			if kind == common.DirectPaymentAdmittedDAG10CircuitType && inputs == 144 {
				if _, err := Circuit(kind, inputs, 2); err == nil {
					t.Fatal("accepted an unsupported DAG capacity")
				}
				continue
			}
			circuit, err := Circuit(kind, inputs, 2)
			if err != nil {
				t.Fatal(err)
			}
			switch payment := circuit.(type) {
			case *direct.PaymentCircuit:
				if !payment.GKR || payment.Transcript != "" || len(payment.Certificate.Nullifiers) != int(inputs) {
					t.Fatalf("incorrect GKR configuration: %d inputs", inputs)
				}
			case *direct.DAGPaymentCircuit:
				if payment.Height != 10 || len(payment.Certificate.Notes) != 512 || len(payment.Levels) != 32 || len(payment.Levels[0]) != 512 || len(payment.Levels[9]) != 1 || len(payment.Certificate.Notes[0].Path) != 0 {
					t.Fatal("incorrect DAG configuration")
				}
			case *direct.AdmittedPaymentCircuit:
				if len(payment.Certificate.Nullifiers) != int(inputs) || len(payment.Balance.Values) != 1 || len(payment.Balance.Outputs) != 2 {
					t.Fatalf("incorrect admitted configuration: %d inputs", inputs)
				}
			default:
				t.Fatalf("unexpected circuit %T", circuit)
			}
		}
		for _, shape := range [][2]uint32{{36, 2}, {128, 2}, {144, 1}, {512, 3}} {
			if _, err := Circuit(kind, shape[0], shape[1]); err == nil {
				t.Fatalf("accepted unsupported %s shape %v", kind, shape)
			}
		}
	}
	plain, err := Circuit(common.DirectPaymentCircuitType, 512, 2)
	if err != nil || plain.(*direct.PaymentCircuit).GKR {
		t.Fatal("ordinary payment unexpectedly enables GKR", err)
	}
}

func TestDecodePaymentConfiguration(t *testing.T) {
	for _, kind := range []common.CircuitType{common.DirectPaymentGKRCircuitType, common.DirectPaymentAdmittedCircuitType, common.DirectPaymentAdmittedDAG10CircuitType} {
		for _, inputs := range []uint32{144, 512} {
			if kind == common.DirectPaymentAdmittedDAG10CircuitType && inputs == 144 {
				continue
			}
			circuit, err := Circuit(kind, inputs, 2)
			if err != nil {
				t.Fatal(err)
			}
			fillFields(reflect.ValueOf(circuit).Elem())
			encoded, err := json.Marshal(circuit)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(Request{CircuitType: kind, NInputs: inputs, NOutputs: 2, Witness: encoded})
			_, assignment, err := Decode(body)
			if err != nil {
				t.Fatal(err)
			}
			if payment, ok := assignment.(*direct.PaymentCircuit); ok {
				if !payment.GKR || payment.Transcript != "" {
					t.Fatal("decoding changed circuit configuration")
				}
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			for field, value := range map[string]string{"GKR": "false", "gkr": "true", "Transcript": `"other"`, "transcript": "null", "options": `{}`, "Height": "32", "height": "16"} {
				fields[field] = json.RawMessage(value)
				witness, _ := json.Marshal(fields)
				body, _ := json.Marshal(Request{CircuitType: kind, NInputs: inputs, NOutputs: 2, Witness: witness})
				if _, _, err := Decode(body); err == nil {
					t.Fatalf("accepted client-controlled %s", field)
				}
				delete(fields, field)
			}
		}
	}
}

func fillFields(value reflect.Value) {
	switch value.Kind() {
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).Tag.Get("gnark") != "-" {
				fillFields(value.Field(i))
			}
		}
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			fillFields(value.Index(i))
		}
	case reflect.Interface:
		value.Set(reflect.ValueOf("0x" + strings.Repeat("0", 64)))
	}
}
