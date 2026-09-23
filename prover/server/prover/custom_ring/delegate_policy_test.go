package custom_ring

import (
	"encoding/json"
	"math/big"
	"testing"
)

func TestDelegateParametersRefuseExemptionFields(t *testing.T) {
	base := sampleParams()
	base.WindowIndex, base.ApprovalRequired = 0, false
	raw, err := json.Marshal(&DelegatePolicyParameters{Policy: *base})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &DelegatePolicyParameters{}); err != nil {
		t.Fatalf("valid delegate request refused: %v", err)
	}
	for _, invalid := range []PolicyParameters{
		func() PolicyParameters { q := *base; q.WindowIndex = 1; return q }(),
		func() PolicyParameters { q := *base; q.ApprovalRequired = true; return q }(),
		func() PolicyParameters { q := *base; q.KeyEscrow = KeyEscrow{Root: big.NewInt(0)}; return q }(),
	} {
		raw, err := json.Marshal(&DelegatePolicyParameters{Policy: invalid})
		if err != nil {
			t.Fatal(err)
		}
		var decoded DelegatePolicyParameters
		if json.Unmarshal(raw, &decoded) == nil {
			t.Fatal("nonzero exemption field admitted")
		}
	}
}
