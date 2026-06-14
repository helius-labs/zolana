package transaction

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

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
	assertEqualWhen(api, notDummy, in.Utxo.Domain, UtxoDomain)
	// Default transact handles only bare UTXOs: program/policy data and zone
	// program id must be zero. Program-owned UTXOs (zone_program_id != 0) are
	// spent via zone_transact with the zone PDA as signer (spec: Program
	// ownership); the default path must not spend them without that authorization.
	assertZeroWhen(api, notDummy, in.Utxo.DataHash)
	assertZeroWhen(api, notDummy, in.Utxo.ZoneDataHash)
	assertZeroWhen(api, notDummy, in.Utxo.ZoneProgramID)

	utxoHash := UtxoHashCircuit(api, in.Utxo)

	// Inclusion: utxoHash is a leaf of the state tree at UtxoTreeRoot.
	statePathIndices := api.ToBinary(in.StatePathIndex, StateTreeHeight)
	stateRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  statePathIndices,
		Path:   in.StatePathElements,
		Height: StateTreeHeight,
	})
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
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: ownerKeyHash,
		NullifierPk:  nullifierPk,
	})
	assertEqualWhen(api, notDummy, ownerHash, in.Utxo.Owner)
	// A real P256-owned input requires the valid shared signature; Solana
	// ownership is verified by SPP out of circuit.
	assertZeroWhen(api, api.Mul(notDummy, isP256), api.Sub(1, env.p256SigValid))

	// Nullifier: Poseidon over the UTXO hash, blinding, and the input's own
	// secret — a canonical field element, inserted into the nullifier tree
	// untruncated.
	nullifier := abstractor.Call(api, NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: in.NullifierSecret,
	})
	assertEqualWhen(api, notDummy, nullifier, in.Nullifier)

	// Non-inclusion: the low leaf is in the nullifier tree and brackets the
	// nullifier (NullifierLowValue < Nullifier < NullifierNextValue).
	lowLeafHash := gadgetlib.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue)
	nfPathIndices := api.ToBinary(in.NullifierLowPathIndex, NullifierTreeHeight)
	nfRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   lowLeafHash,
		Index:  nfPathIndices,
		Path:   in.NullifierLowPathElements,
		Height: NullifierTreeHeight,
	})
	assertEqualWhen(api, notDummy, nfRoot, in.NullifierTreeRoot)
	assertStrictlyOrdered(api, in.IsDummy, in.NullifierLowValue, in.Nullifier, in.NullifierNextValue)

	return api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
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

// NullifierPkGadget derives the public nullifier key from the secret (step 2).
type NullifierPkGadget struct {
	NullifierSecret frontend.Variable
}

func (gadget NullifierPkGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.NullifierSecret})
}

// NullifierGadget derives a nullifier from the UTXO hash, its blinding, and the
// spender's nullifier secret (step 4.3).
type NullifierGadget struct {
	UtxoHash        frontend.Variable
	Blinding        frontend.Variable
	NullifierSecret frontend.Variable
}

func (gadget NullifierGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		gadget.UtxoHash,
		gadget.Blinding,
		gadget.NullifierSecret,
	})
}

// AssertStrictlyOrdered constrains lo < mid < hi for a real entry, comparing
// full field values (see gadget.IsLessLimbs) — the nullifier tree's
// indexed-value domain spans the whole field. Dummy entries (IsDummy == 1) are
// remapped to 0 < 1 < 2, so the check always passes for them. Backs the
// non-inclusion check in step 4.5.
type AssertStrictlyOrdered struct {
	IsDummy frontend.Variable
	Lo      frontend.Variable
	Mid     frontend.Variable
	Hi      frontend.Variable
}

func (gadget AssertStrictlyOrdered) DefineGadget(api frontend.API) interface{} {
	lo := api.Select(gadget.IsDummy, frontend.Variable(0), gadget.Lo)
	mid := api.Select(gadget.IsDummy, frontend.Variable(1), gadget.Mid)
	hi := api.Select(gadget.IsDummy, frontend.Variable(2), gadget.Hi)
	loLimbs := gadgetlib.CanonicalLimbs(api, lo)
	midLimbs := gadgetlib.CanonicalLimbs(api, mid)
	hiLimbs := gadgetlib.CanonicalLimbs(api, hi)
	api.AssertIsEqual(gadgetlib.IsLessLimbs(api, loLimbs, midLimbs), 1)
	api.AssertIsEqual(gadgetlib.IsLessLimbs(api, midLimbs, hiLimbs), 1)
	return []frontend.Variable{}
}

func assertStrictlyOrdered(api frontend.API, isDummy, lo, mid, hi frontend.Variable) {
	abstractor.CallVoid(api, AssertStrictlyOrdered{IsDummy: isDummy, Lo: lo, Mid: mid, Hi: hi})
}
