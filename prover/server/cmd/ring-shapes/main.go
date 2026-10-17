// Prints the registered policy shape catalog for key generation.
package main

import (
	"encoding/json"
	"os"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func main() {
	type entry struct {
		Circuit   common.CircuitType `json:"circuit"`
		Inputs    int                `json:"inputs"`
		Outputs   int                `json:"outputs"`
		Anonymous bool               `json:"anonymous"`
		Delegate  bool               `json:"delegate"`
		Subtree   bool               `json:"subtree"`
	}
	entries := make([]entry, len(common.RingPolicyShapes))
	for i, shape := range common.RingPolicyShapes {
		entries[i] = entry{shape.CircuitType(), shape.NInputs, shape.NOutputs, shape.Anonymous, shape.Delegate, shape.Subtree}
	}
	if err := json.NewEncoder(os.Stdout).Encode(entries); err != nil {
		panic(err)
	}
}
