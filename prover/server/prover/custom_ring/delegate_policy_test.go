package custom_ring

import (
	"encoding/json"
	"testing"
)

func TestDelegateParametersRefuseExemptionFields(t *testing.T) {
	base := sampleParams()
	base.WindowIndex, base.ApprovalRequired = 0, false
	for _, invalid := range []PolicyParameters{
		func() PolicyParameters { q := *base; q.WindowIndex = 1; return q }(),
		func() PolicyParameters { q := *base; q.ApprovalRequired = true; return q }(),
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
