package common

import (
	"fmt"
	"testing"
)

func TestGKRRequestMeta(t *testing.T) {
	for _, kind := range []CircuitType{DirectPaymentGKRCircuitType, DirectPaymentAdmittedCircuitType} {
		meta, err := ParseProofRequestMeta([]byte(fmt.Sprintf(`{"circuitType":%q,"nInputs":144,"nOutputs":2,"witness":{}}`, kind)))
		if err != nil {
			t.Fatal(err)
		}
		if meta.CircuitType != kind || meta.NumInputs != 144 || meta.NumOutputs != 2 {
			t.Fatalf("incorrect metadata: %+v", meta)
		}
	}
}
