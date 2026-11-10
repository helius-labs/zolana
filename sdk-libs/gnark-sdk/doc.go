// Package gnarksdk is the circuit side of a ZK program that proves relations
// over shielded-pool transactions with gnark Groth16: the UTXO witness, its
// hash, the private transaction hash and the blinding derivations. Every
// relation is built from the canonical gadgets in
// github.com/helius-labs/zolana/prover/server, so a circuit
// computes the values the shielded pool and spr-client compute and adds no
// second implementation of them.
//
// A circuits module outside this repository requires this module and
// github.com/helius-labs/zolana/prover/server at the same Zolana commit, one
// that already has this module path, as pseudo-versions:
//
//	go get github.com/helius-labs/zolana/sdk-libs/gnark-sdk@<commit>
//	go get github.com/helius-labs/zolana/prover/server/circuits/gadget@<commit>
//
// The second names a circuit package rather than the module root: the root is
// the prover server, whose GPU backend imports a private module.
//
// It also repeats prover/server's replacement of
// github.com/reilabs/gnark-lean-extractor/v3, because Go does not apply the
// replacements of a dependency's go.mod. Circuits inside this repository
// replace both modules with their directories.
//
// The transaction helpers never check membership, signatures or program
// authorization; the shielded pool's transact proof over the same private
// transaction hash does. UtxoRead is the exception: a read has no transact
// proof, so it proves state-tree membership and nullifier-tree non-membership
// itself.
package gnarksdk
