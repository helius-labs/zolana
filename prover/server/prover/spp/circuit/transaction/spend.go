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

// spendEnv holds values shared by every input-spend check. They are computed
// once per proof from the wallet secret and the single P256 signer.
type spendEnv struct {
	nullifierPkFromSecret frontend.Variable
	p256OwnerKeyHash      frontend.Variable
	p256SigValid          frontend.Variable
	nullifierSecret       frontend.Variable
	// requiresP256 is false for the Solana-only circuit variant, which omits the
	// P256 gadget and must therefore reject any real P256-owned input.
	requiresP256 bool
}

// constrainInput verifies one spent input: domain, state-tree inclusion, owner
// binding, nullifier derivation, and nullifier-tree non-inclusion. Every check
// is gated on the slot being real; a dummy slot skips all of them. It returns
// the input's UTXO hash (0 for a dummy) for the transaction-hash chain.
func constrainInput(api frontend.API, in Input, env spendEnv) frontend.Variable {
	api.AssertIsBoolean(in.IsDummy)
	notDummy := api.Sub(1, in.IsDummy)

	// A dummy slot must be inert: zero amount and zero public-input material.
	assertZeroWhen(api, in.IsDummy, in.Utxo.AssetAmount)
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
	// A dummy slot's root is meaningless; pin it to 0 so the public transcript
	// is canonical (matches the on-chain zero-padded reconstruction) rather than
	// relying on that reducer alone to canonicalize it.
	assertZeroWhen(api, in.IsDummy, in.UtxoTreeRoot)

	// Owner check: P256 inputs (SolanaPkHash == 0) rebuild the owner key hash
	// from the P256 point in the witness; Solana inputs use the public hash.
	isP256 := api.IsZero(in.SolanaPkHash)
	if !env.requiresP256 {
		// Solana-only variant: the P256 gadget (incl. the signature check) is
		// absent, so a real input MUST be Solana-owned (SolanaPkHash != 0).
		// Otherwise p256OwnerKeyHash is 0 and p256SigValid is forced 1, which
		// would let a UTXO crafted with owner = OwnerHash(0, nullifier_pk) be
		// spent here with no signature. This restricts the variant to its rail.
		assertZeroWhen(api, notDummy, isP256)
	}
	ownerKeyHash := api.Select(isP256, env.p256OwnerKeyHash, in.SolanaPkHash)
	ownerHash := OwnerHashCircuit(api, ownerKeyHash, env.nullifierPkFromSecret)
	assertEqualWhen(api, notDummy, ownerHash, in.Utxo.Owner)
	// Real P256 inputs must carry a valid signature; Solana inputs are verified
	// by SPP out of circuit. Dummy slots carry SolanaPkHash == 0.
	assertZeroWhen(api, api.Mul(notDummy, isP256), api.Sub(1, env.p256SigValid))
	assertZeroWhen(api, in.IsDummy, in.SolanaPkHash)

	// Nullifier: Poseidon over the UTXO hash, blinding, and shared secret — a
	// canonical field element, inserted into the nullifier tree untruncated.
	nullifier := NullifierHashCircuit(api, utxoHash, in.Utxo.Blinding, env.nullifierSecret)
	assertEqualWhen(api, notDummy, nullifier, in.Nullifier)
	assertZeroWhen(api, in.IsDummy, in.Nullifier)

	// Non-inclusion: the low leaf is in the nullifier tree and brackets the
	// nullifier (NullifierLowValue < Nullifier < NullifierNextValue).
	lowLeafHash := gadget.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue)
	nfPathIndices := api.ToBinary(in.NullifierLowPathIndex, protocol.NullifierTreeHeight)
	nfRoot := gadget.MerkleRoot(api, lowLeafHash, in.NullifierLowPathElements, nfPathIndices)
	assertEqualWhen(api, notDummy, nfRoot, in.NullifierRoot)
	assertZeroWhen(api, in.IsDummy, in.NullifierRoot)
	assertStrictlyOrdered(api, in.IsDummy, in.NullifierLowValue, in.Nullifier, in.NullifierNextValue)

	return api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
}

// constrainOutput verifies one created output and returns its UTXO hash (0 for a
// dummy) for the transaction-hash chain.
func constrainOutput(api frontend.API, out Output) frontend.Variable {
	api.AssertIsBoolean(out.IsDummy)
	notDummy := api.Sub(1, out.IsDummy)

	assertZeroWhen(api, out.IsDummy, out.Utxo.AssetAmount)
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
// inputs all carry nullifier 0 and are excluded from the check.
func (c *Circuit) assertDistinctNullifiers(api frontend.API) {
	for i := range c.Inputs {
		for j := i + 1; j < len(c.Inputs); j++ {
			bothReal := api.Mul(api.Sub(1, c.Inputs[i].IsDummy), api.Sub(1, c.Inputs[j].IsDummy))
			sameNullifier := api.IsZero(api.Sub(c.Inputs[i].Nullifier, c.Inputs[j].Nullifier))
			api.AssertIsEqual(api.Mul(bothReal, sameNullifier), 0)
		}
	}
}

// assertSingleOwner enforces the spec's single-owner rule (spec.md "Nullifier
// secret binding": all non-dummy inputs share nullifier_pk and therefore the
// same owner). Every pair of real inputs must carry the same owner_hash; since
// the nullifier_pk is already shared (one nullifier_secret), this forces a single
// signing key — no mixing P256 with Solana, or distinct Solana keys, in one
// transaction. Dummy slots are excluded.
func (c *Circuit) assertSingleOwner(api frontend.API) {
	for i := range c.Inputs {
		for j := i + 1; j < len(c.Inputs); j++ {
			bothReal := api.Mul(api.Sub(1, c.Inputs[i].IsDummy), api.Sub(1, c.Inputs[j].IsDummy))
			api.AssertIsEqual(api.Mul(bothReal, api.Sub(c.Inputs[i].Utxo.Owner, c.Inputs[j].Utxo.Owner)), 0)
		}
	}
}
