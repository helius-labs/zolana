// Prints the keys a ring key rotation sets up, generate_ring_keys.py reads it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/consensys/gnark/constraint"
	gnarkLogger "github.com/consensys/gnark/logger"
	"golang.org/x/sync/errgroup"

	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	customring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
	"github.com/helius-labs/zolana/prover/server/prover/request"
)

type entry struct {
	// Kind is "ring" for a custom ring key, "spp" for an SPP ring rail key.
	Kind    string             `json:"kind"`
	Circuit common.CircuitType `json:"circuit"`
	File    string             `json:"file"`
	// Setup is the prover command writing the key, its --output path follows.
	Setup  []string `json:"setup"`
	Module string   `json:"module,omitempty"`
	// Rust is the key's RingCircuit value in custom-rings/interface/src/key_catalog.rs, empty on an SPP key.
	Rust        string `json:"rust,omitempty"`
	Constraints int    `json:"constraints,omitempty"`
	Public      int    `json:"public,omitempty"`
	Commitments *int   `json:"commitments,omitempty"`
	compile     func() (constraint.ConstraintSystem, error)
}

func main() {
	compile := flag.Bool("compile", false, "compile the key files named after the flags, every key without one, and report constraints, public inputs and BSB22 commitments")
	jobs := flag.Int("jobs", 4, "circuits compiled at once")
	flag.Parse()
	entries := append(ringEntries(), sppEntries()...)
	if *compile {
		// gnark logs to stdout, the catalog owns it.
		gnarkLogger.Disable()
		if err := measure(entries, flag.Args(), *jobs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(entries); err != nil {
		panic(err)
	}
}

func ringEntries() []entry {
	entries := make([]entry, len(common.RingKeys))
	for i, key := range common.RingKeys {
		file := common.RingKeyFile(key.Circuit)
		ring, err := customring.Ring(key.Circuit)
		if err != nil {
			panic(err)
		}
		entries[i] = entry{
			Kind:    "ring",
			Circuit: key.Circuit,
			File:    file,
			Setup:   []string{"setup-" + string(key.Circuit)},
			Module:  strings.TrimSuffix(strings.TrimPrefix(file, "custom_ring_"), ".key") + "_verifying_key",
			Rust:    rustCircuit(key),
			compile: ring.R1CS,
		}
	}
	return entries
}

// rustCircuit is Rust source, generate_ring_keys.py pastes it after RingCircuit:: into the interface crate.
func rustCircuit(key common.RingKey) string {
	switch key.Family {
	case common.RingPackedAudit:
		return fmt.Sprintf("PackedAudit { outputs: %d }", key.Outputs)
	case common.RingDeliveredAudit:
		return fmt.Sprintf("DeliveredAudit { outputs: %d }", key.Outputs)
	case common.RingAnonymousAudit:
		return fmt.Sprintf("AnonymousAudit { class: %d, outputs: %d }", key.Inputs, key.Outputs)
	case common.RingAnonymousEntryAudit:
		return fmt.Sprintf("AnonymousEntryAudit { class: %d, outputs: %d }", key.Inputs, key.Outputs)
	case common.RingMemberPolicy:
		return fmt.Sprintf("MemberPolicy { outputs: %d }", key.Outputs)
	case common.RingDelegatePolicy:
		return fmt.Sprintf("DelegatePolicy { inputs: %d, outputs: %d }", key.Inputs, key.Outputs)
	case common.RingApplyRecords:
		return fmt.Sprintf("ApplyRecords { writes: %d }", key.Inputs)
	case common.RingRegisterKey:
		return "RegisterKey"
	case common.RingDeposit:
		return "Deposit"
	case common.RingAnonymousMerge:
		return fmt.Sprintf("AnonymousMerge { width: %d }", key.Inputs)
	}
	panic(fmt.Sprintf("ring-shapes: no Rust circuit for family %d", key.Family))
}

// sppEntries are the SPP rails whose statements open ring secrets or member records, their keys rotate with the ring keys.
func sppEntries() []entry {
	var entries []entry
	for _, circuit := range []common.CircuitType{
		common.TransferRingCircuitType,
		common.TransferAnonymousRingEddsaCircuitType,
		common.TransferRingAuthorityCircuitType,
	} {
		for _, shape := range common.TransferShapes {
			key := common.ProofShape{Circuit: circuit, Inputs: uint32(shape.NInputs), Outputs: uint32(shape.NOutputs)}
			setup := []string{"setup-transfer", "--circuit", string(circuit), "--n-inputs", strconv.Itoa(shape.NInputs), "--n-outputs", strconv.Itoa(shape.NOutputs)}
			if e := sppEntry(key, setup); e.File != "" {
				entries = append(entries, e)
			}
		}
	}
	for _, n := range mergeshared.SupportedInputCounts {
		key := common.ProofShape{Circuit: common.MergeRingCircuitType, Inputs: uint32(n), Outputs: 1}
		entries = append(entries, sppEntry(key, []string{"setup-merge", "--circuit", string(key.Circuit), "--n-inputs", strconv.Itoa(n)}))
	}
	return entries
}

// sppEntry is the key of shape, File empty when no key serves it.
func sppEntry(shape common.ProofShape, setup []string) entry {
	return entry{
		Kind: "spp", Circuit: shape.Circuit, File: common.TransferKeyFile(shape.Circuit, shape.Inputs, shape.Outputs), Setup: setup,
		compile: func() (constraint.ConstraintSystem, error) { return request.R1CS(shape) },
	}
}

func measure(entries []entry, files []string, jobs int) error {
	var group errgroup.Group
	group.SetLimit(jobs)
	for i := range entries {
		if len(files) != 0 && !slices.Contains(files, entries[i].File) {
			continue
		}
		group.Go(func() error {
			cs, err := entries[i].compile()
			if err != nil {
				return fmt.Errorf("%s: %w", entries[i].File, err)
			}
			commitments := 0
			if groth16, ok := cs.GetCommitments().(constraint.Groth16Commitments); ok {
				commitments = len(groth16)
			}
			// gnark counts the constant one wire as a public variable.
			entries[i].Constraints, entries[i].Public, entries[i].Commitments = cs.GetNbConstraints(), cs.GetNbPublicVariables()-1, &commitments
			return nil
		})
	}
	return group.Wait()
}
