// Package gnarksdk is the circuit side of a ZK program that proves relations
// over shielded-pool transactions with gnark Groth16: the UTXO witness, its
// hash, the private transaction hash and the blinding derivations. Every
// relation is built from the canonical gadgets in zolana/prover, so a circuit
// computes the values the shielded pool and zolana-client compute and adds no
// second implementation of them.
//
// A circuits module that imports this package requires zolana/gnarksdk and
// replaces both it and zolana/prover with their directories, because Go does
// not apply the replacements of a dependency's go.mod:
//
//	replace zolana/gnarksdk => <repo>/sdk-libs/gnark-sdk
//	replace zolana/prover => <repo>/prover/server
//
// The helpers never check membership, signatures or program authorization;
// the shielded pool's transact proof over the same private transaction hash
// does.
package gnarksdk
