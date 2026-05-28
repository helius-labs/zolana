// Package spp contains the Shielded Pool Program proof circuit.
//
// The SPP spec is the source of truth. SPP uses one Groth16 proof for one
// circuit per supported (N inputs, M outputs) shape. The MASP reference in
// ../shielded-pool is useful for gadgets and test patterns, but its two-circuit
// UTXO/tree proof split is intentionally not mirrored here.
package spp
