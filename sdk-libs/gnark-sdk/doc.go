// Package gnarksdk is the circuit side of a ZK program that proves relations
// over shielded-pool transactions with gnark Groth16: the UTXO witness, its
// hash, the private transaction hash and the blinding derivations. Every
// relation is built from the canonical gadgets in
// github.com/helius-labs/zolana/prover/server, so a circuit computes the values
// the shielded pool and spr-client compute and adds no second implementation
// of them.
//
// A circuits module that imports this package requires zolana/gnarksdk and
// repeats this module's replacements, because Go does not apply the
// replacements of a dependency's go.mod:
//
//	replace zolana/gnarksdk => <repo>/sdk-libs/gnark-sdk
//	replace github.com/helius-labs/zolana/prover/server => <repo>/prover/server
//	replace github.com/reilabs/gnark-lean-extractor/v3 => github.com/Lightprotocol/gnark-lean-extractor/v3 v3.0.0-20250920122823-aa0219463107
//
// The transaction helpers never check membership, signatures or program
// authorization; the shielded pool's transact proof over the same private
// transaction hash does. UtxoRead is the exception: a read has no transact
// proof, so it proves state-tree membership and nullifier-tree non-membership
// itself.
package gnarksdk
