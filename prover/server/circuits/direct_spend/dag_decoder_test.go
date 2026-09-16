package directspend_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/consensys/gnark/frontend"

	direct "zolana/prover/circuits/direct_spend"
	"zolana/prover/prover/common"
	directprover "zolana/prover/prover/direct_spend"
)

func dagFactory(inputs, height int) func(common.CircuitType, uint32, uint32) (frontend.Circuit, error) {
	return func(kind common.CircuitType, n, outputs uint32) (frontend.Circuit, error) {
		if kind != "admitted-dag-experiment" || n != uint32(inputs) || outputs != 2 {
			return nil, fmt.Errorf("unsupported experimental DAG shape")
		}
		return direct.NewDAGAdmittedPayment(inputs, height), nil
	}
}

func dagRequest(t *testing.T, w *direct.DAGAdmittedPayment) []byte {
	t.Helper()
	witness, err := json.Marshal(witnessJSON(t, reflect.ValueOf(w).Elem()))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(directprover.Request{
		CircuitType: "admitted-dag-experiment", NInputs: uint32(len(w.Certificate.Notes)), NOutputs: 2, Witness: witness,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestAdmittedDAGDecode(t *testing.T) {
	w := dagAdmittedPayment(t, scatteredPaymentAtHeight(t, 4, 10), 10)
	body := dagRequest(t, w)
	if _, _, err := directprover.DecodeWithFactory(body, dagFactory(4, 10)); err != nil {
		t.Fatal(err)
	}
	var request directprover.Request
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(request.Witness, &fields); err != nil {
		t.Fatal(err)
	}
	fields["Height"] = json.RawMessage("32")
	request.Witness, _ = json.Marshal(fields)
	body, _ = json.Marshal(request)
	if _, _, err := directprover.DecodeWithFactory(body, dagFactory(4, 10)); err == nil {
		t.Fatal("accepted client-controlled DAG height")
	}
}
