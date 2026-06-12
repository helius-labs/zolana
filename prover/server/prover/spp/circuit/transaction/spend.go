package transaction

import (
	"light/light-prover/prover/spp/circuit/gadget"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark/frontend"
)

// assertEqualWhen constrains a == b only when cond == 1. For cond == 0 the
// product is 0 regardless, so the check is vacuously satisfied (skipped).
func assertEqualWhen(api frontend.API, cond, a, b frontend.Variable) {
	api.AssertIsEqual(api.Mul(cond, api.Sub(a, b)), 0)
}

// assertZeroWhen constrains v == 0 only when cond == 1.
func assertZeroWhen(api frontend.API, cond, v frontend.Variable) {
	api.AssertIsEqual(api.Mul(cond, v), 0)
}

// assertStrictlyOrdered constrains lo < mid < hi for a real entry, comparing
// full field values (see compare.go) — the nullifier tree's indexed-value
// domain spans the whole field. Dummy entries (isDummy == 1) are remapped to
// 0 < 1 < 2, so the check always passes for them.
func assertStrictlyOrdered(api frontend.API, isDummy, lo, mid, hi frontend.Variable) {
	lo = api.Select(isDummy, frontend.Variable(0), lo)
	mid = api.Select(isDummy, frontend.Variable(1), mid)
	hi = api.Select(isDummy, frontend.Variable(2), hi)
	loLimbs := canonicalLimbs(api, lo)
	midLimbs := canonicalLimbs(api, mid)
	hiLimbs := canonicalLimbs(api, hi)
	api.AssertIsEqual(isLessLimbs(api, loLimbs, midLimbs), 1)
	api.AssertIsEqual(isLessLimbs(api, midLimbs, hiLimbs), 1)
}

// spendEnv holds the per-proof values shared by every input-spend check: the
// one witnessed P256 key and the one signature over private_tx_hash that
// authorize all P256-owned inputs.
type spendEnv struct {
	p256PkField  frontend.Variable
	p256SigValid frontend.Variable
	// requiresP256 is false for the Solana-only circuit variant, which omits the
	// P256 gadget and must therefore reject P256-owned inputs.
	requiresP256 bool
}

// constrainInput verifies one spent input: domain, state-tree inclusion, owner
// binding, nullifier derivation, and nullifier-tree non-inclusion. Every check
// is gated on the slot being real; a dummy slot skips all of them. It returns
// the input's UTXO hash (0 for a dummy) for the transaction-hash chain.
func constrainInput(api frontend.API, in Input, nullifierPk frontend.Variable, env spendEnv) frontend.Variable {
	api.AssertIsBoolean(in.IsDummy)
	notDummy := api.Sub(1, in.IsDummy)

	// A dummy slot must be inert: zero amount. Its public transcript columns
	// (nullifier, roots, owner entry) are deliberately unpinned so a dummy can
	// mimic a real slot and hide the transaction's real arity; the on-chain
	// reconstruction decides what values it accepts there.
	assertZeroWhen(api, in.IsDummy, in.Utxo.Amount)
	assertEqualWhen(api, notDummy, in.Utxo.Domain, protocol.UtxoDomain)
	// Default transact handles only bare UTXOs: program/policy data and zone
	// program id must be zero. Program-owned UTXOs (zone_program_id != 0) are
	// spent via zone_transact with the zone PDA as signer (spec: Program
	// ownership); the default path must not spend them without that authorization.
	assertZeroWhen(api, notDummy, in.Utxo.DataHash)
	assertZeroWhen(api, notDummy, in.Utxo.ZoneDataHash)
	assertZeroWhen(api, notDummy, in.Utxo.ZoneProgramID)

	utxoHash := UtxoHashCircuit(api, in.Utxo)

	// Inclusion: utxoHash is a leaf of the state tree at UtxoTreeRoot.
	statePathIndices := api.ToBinary(in.StatePathIndex, protocol.StateTreeHeight)
	stateRoot := gadget.MerkleRoot(api, utxoHash, in.StatePathElements, statePathIndices)
	assertEqualWhen(api, notDummy, stateRoot, in.UtxoTreeRoot)

	// Owner check: the input's SolanaOwnerPkHash selects its path —
	// 0 binds the owner to the shared witnessed P256 key,
	// non-zero binds it to the entry itself
	isP256 := api.IsZero(in.SolanaOwnerPkHash)
	if !env.requiresP256 {
		// Solana-only variant: the P256 gadget (incl. the signature check) is
		// absent, so every real input MUST be Solana-owned (entry != 0).
		// Otherwise the owner key is 0 and p256SigValid is forced 1, which would
		// let a UTXO crafted with owner = OwnerHash(0, nullifier_pk) be spent
		// here with no signature. This restricts the variant to its rail.
		assertZeroWhen(api, notDummy, isP256)
	}
	ownerKeyHash := api.Select(isP256, env.p256PkField, in.SolanaOwnerPkHash)
	ownerHash := OwnerHashCircuit(api, ownerKeyHash, nullifierPk)
	assertEqualWhen(api, notDummy, ownerHash, in.Utxo.Owner)
	// A real P256-owned input requires the valid shared signature; Solana
	// ownership is verified by SPP out of circuit.
	assertZeroWhen(api, api.Mul(notDummy, isP256), api.Sub(1, env.p256SigValid))

	// Nullifier: Poseidon over the UTXO hash, blinding, and the input's own
	// secret — a canonical field element, inserted into the nullifier tree
	// untruncated.
	nullifier := NullifierCircuit(api, utxoHash, in.Utxo.Blinding, in.NullifierSecret)
	assertEqualWhen(api, notDummy, nullifier, in.Nullifier)

	// Non-inclusion: the low leaf is in the nullifier tree and brackets the
	// nullifier (NullifierLowValue < Nullifier < NullifierNextValue).
	lowLeafHash := gadget.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue)
	nfPathIndices := api.ToBinary(in.NullifierLowPathIndex, protocol.NullifierTreeHeight)
	nfRoot := gadget.MerkleRoot(api, lowLeafHash, in.NullifierLowPathElements, nfPathIndices)
	assertEqualWhen(api, notDummy, nfRoot, in.NullifierTreeRoot)
	assertStrictlyOrdered(api, in.IsDummy, in.NullifierLowValue, in.Nullifier, in.NullifierNextValue)

	return api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
}

// constrainOutput verifies one created output and returns its UTXO hash (0 for a
// dummy) for the transaction-hash chain.
func constrainOutput(api frontend.API, out Output) frontend.Variable {
	api.AssertIsBoolean(out.IsDummy)
	notDummy := api.Sub(1, out.IsDummy)

	assertZeroWhen(api, out.IsDummy, out.Utxo.Amount)
	assertEqualWhen(api, notDummy, out.Utxo.Domain, protocol.UtxoDomain)
	// Default transact creates only bare UTXOs (no program/policy/zone data).
	assertZeroWhen(api, notDummy, out.Utxo.DataHash)
	assertZeroWhen(api, notDummy, out.Utxo.ZoneDataHash)
	assertZeroWhen(api, notDummy, out.Utxo.ZoneProgramID)

	utxoHash := UtxoHashCircuit(api, out.Utxo)
	assertEqualWhen(api, notDummy, utxoHash, out.Hash)
	assertZeroWhen(api, out.IsDummy, out.Hash)

	return api.Select(out.IsDummy, frontend.Variable(0), utxoHash)
}

// assertDistinctNullifiers rejects spending the same input twice in one
// transaction: every pair of real inputs must carry distinct nullifiers. Dummy
// inputs are excluded from the check.
func (c *Circuit) assertDistinctNullifiers(api frontend.API) {
	for i := range c.Inputs {
		for j := i + 1; j < len(c.Inputs); j++ {
			bothReal := api.Mul(api.Sub(1, c.Inputs[i].IsDummy), api.Sub(1, c.Inputs[j].IsDummy))
			sameNullifier := api.IsZero(api.Sub(c.Inputs[i].Nullifier, c.Inputs[j].Nullifier))
			api.AssertIsEqual(api.Mul(bothReal, sameNullifier), 0)
		}
	}
}
