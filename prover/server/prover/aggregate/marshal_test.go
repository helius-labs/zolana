package aggregate

import (
	"encoding/json"
	"fmt"
	"testing"

	"zolana/prover/prover/common"
)

func legJSON(inner string, nInputs, nOutputs uint32) string {
	leg := `"proof":{"ar":["0x0","0x0"],"bs":[["0x0","0x0"],["0x0","0x0"]],"krs":["0x0","0x0"]},"publicInputHash":"0x1"`
	if inner != "" {
		leg += fmt.Sprintf(`,"innerCircuitType":%q,"nInputs":%d,"nOutputs":%d`, inner, nInputs, nOutputs)
	}
	return "{" + leg + "}"
}

// A request without per-leg kinds is the uniform batch, keyed by the
// request-level rail and shape.
func TestUnmarshalUniformRequest(t *testing.T) {
	raw := fmt.Sprintf(
		`{"circuitType":"aggregate","innerCircuitType":"transfer-ring","nInputs":2,"nOutputs":3,"legs":[%s,%s]}`,
		legJSON("", 0, 0), legJSON("", 0, 0),
	)
	var p Parameters
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if want := Uniform(common.TransferRingCircuitType, 2, 3, 2); p.Params.KeyName() != want.KeyName() {
		t.Errorf("params resolve to %s, want %s", p.Params.KeyName(), want.KeyName())
	}
}

// A leg that names its own kind overrides the request-level one, so a mixed
// batch is a list of self-describing legs.
func TestUnmarshalMixedRequest(t *testing.T) {
	raw := fmt.Sprintf(
		`{"circuitType":"aggregate","innerCircuitType":"transfer-confidential","nInputs":2,"nOutputs":2,"legs":[%s,%s]}`,
		legJSON("swap-take", 0, 0), legJSON("", 0, 0),
	)
	var p Parameters
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	want := Params{Slots: []common.AggregateSlot{
		{Inner: common.SwapTakeCircuitType},
		{Inner: common.TransferConfidentialCircuitType, NInputs: 2, NOutputs: 2},
	}}
	if p.Params.KeyName() != want.KeyName() {
		t.Errorf("params resolve to %s, want %s", p.Params.KeyName(), want.KeyName())
	}
}

func TestUnmarshalRejectsAnUnsettleableMix(t *testing.T) {
	raw := fmt.Sprintf(
		`{"circuitType":"aggregate","innerCircuitType":"swap-take","nInputs":0,"nOutputs":0,"legs":[%s,%s]}`,
		legJSON("", 0, 0), legJSON("", 0, 0),
	)
	var p Parameters
	if err := json.Unmarshal([]byte(raw), &p); err == nil {
		t.Error("a batch of only take slots was accepted")
	}
}
