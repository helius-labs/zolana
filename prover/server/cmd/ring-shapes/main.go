// Prints the registered policy shape catalog for key generation.
package main

import (
	"encoding/json"
	"flag"
	"os"
	"strings"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func main() {
	keys := flag.Bool("keys", false, "include every custom-ring key and its release metadata")
	flag.Parse()
	type entry struct {
		Circuit   common.CircuitType `json:"circuit"`
		Inputs    int                `json:"inputs"`
		Outputs   int                `json:"outputs"`
		Anonymous bool               `json:"anonymous"`
		Delegate  bool               `json:"delegate"`
		Subtree   bool               `json:"subtree"`
		Section   string             `json:"section,omitempty"`
		File      string             `json:"file,omitempty"`
		Module    string             `json:"module,omitempty"`
	}
	entries := make([]entry, 0, len(common.RingPolicyShapes)+len(common.RingCircuitTypes))
	if *keys {
		for _, circuit := range common.RingCircuitTypes {
			if _, shaped := common.ParseRingPolicyShape(circuit); shaped {
				continue
			}
			entries = append(entries, entry{Circuit: circuit})
		}
	}
	for _, shape := range common.RingPolicyShapes {
		entries = append(entries, entry{Circuit: shape.CircuitType(), Inputs: shape.NInputs, Outputs: shape.NOutputs, Anonymous: shape.Anonymous, Delegate: shape.Delegate, Subtree: shape.Subtree})
	}
	if *keys {
		for i := range entries {
			e := &entries[i]
			e.File = common.RingKeyFile(e.Circuit)
			stem := strings.TrimSuffix(strings.TrimPrefix(e.File, "custom_ring_"), ".key")
			e.Module = stem + "_verifying_key"
			e.Section = stem + "_key"
			// Existing release section names remain stable across key rotations.
			switch e.Circuit {
			case common.CustomRingPolicyCircuitType:
				e.Section = "proving_key"
			case common.CustomRingBaseCircuitType:
				e.Section = "audit_key"
			case common.CustomRingConfidentialCircuitType:
				e.Section = "confidential_audit_key"
			case common.CustomRingAnonymousPolicyTwoByThreeCircuitType:
				e.Section = "anonymous_policy_2x3_key"
			case common.CustomRingKeyRegisterCircuitType:
				e.Section = "register_key"
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(entries); err != nil {
		panic(err)
	}
}
