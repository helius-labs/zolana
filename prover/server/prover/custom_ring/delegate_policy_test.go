package custom_ring

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDelegateParametersKeepTableAndPinExemptionFields(t *testing.T) {
	base := sampleParams()
	base.WindowIndex, base.ApprovalRequired = 0, false
	p := DelegatePolicyParameters{Policy: *base}
	raw, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DelegatePolicyParameters
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(&decoded)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("round trip: %v", err)
	}
	if decoded.Policy.WindowSlots != base.WindowSlots || decoded.Policy.VelocityCount != base.VelocityCount {
		t.Fatal("delegate exemption dropped committed velocity configuration")
	}
	for _, invalid := range []PolicyParameters{
		func() PolicyParameters { q := *base; q.WindowIndex = 1; return q }(),
		func() PolicyParameters { q := *base; q.ApprovalRequired = true; return q }(),
	} {
		raw, err := json.Marshal(&DelegatePolicyParameters{Policy: invalid})
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(raw, &decoded) == nil {
			t.Fatal("nonzero exemption field admitted")
		}
	}
}
