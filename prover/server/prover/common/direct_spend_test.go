package common

import (
	"fmt"
	"testing"
)

func TestGKRRequestMeta(t *testing.T) {
	for _, kind := range []CircuitType{DirectPaymentGKRCircuitType, DirectPaymentAdmittedCircuitType, DirectPaymentAdmittedDAG10CircuitType} {
		meta, err := ParseProofRequestMeta([]byte(fmt.Sprintf(`{"circuitType":%q,"nInputs":512,"nOutputs":2,"witness":{}}`, kind)))
		if err != nil {
			t.Fatal(err)
		}
		if meta.CircuitType != kind || meta.NumInputs != 512 || meta.NumOutputs != 2 {
			t.Fatalf("incorrect metadata: %+v", meta)
		}
	}
}
