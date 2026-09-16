package common

import "testing"

func TestGKRRequestMeta(t *testing.T) {
	meta, err := ParseProofRequestMeta([]byte(`{"circuitType":"direct-payment-gkr","nInputs":144,"nOutputs":2,"witness":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if meta.CircuitType != DirectPaymentGKRCircuitType || meta.NumInputs != 144 || meta.NumOutputs != 2 {
		t.Fatalf("incorrect metadata: %+v", meta)
	}
}
