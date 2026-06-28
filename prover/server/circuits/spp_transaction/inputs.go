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
	// confidential routes ownership by equality to p256SigningPkField (the shared
	// P256 key's pk_field) instead of the 0 sentinel, so P256 input owners are public.
	confidential       bool
	p256SigningPkField frontend.Variable
	zone               bool
	zoneAuthority      bool
	programID          frontend.Variable
	zoneProgramID      frontend.Variable
}

// constrainProgramZone binds a UTXO's zone fields. The program_id/program_data
// binding moved to the callers: program identity is the owner, so the standalone
// program_id field is pinned to 0 and program data is allowed only on
// program-owned UTXOs (see constrainInput / constrainOutput).
func constrainProgramZone(api frontend.API, notDummy frontend.Variable, u UtxoCircuitFields, zone, strictZone bool, zoneProgramID frontend.Variable) {
	if zone {
		if strictZone {
			assertEqualWhen(api, notDummy, u.ZoneProgramID, zoneProgramID)
		} else {
			bindIfSet(api, notDummy, u.ZoneProgramID, zoneProgramID)
		}
		requireIdWhenDataSet(api, notDummy, u.ZoneDataHash, u.ZoneProgramID)
	} else {
		assertZeroWhen(api, notDummy, u.ZoneDataHash)
		assertZeroWhen(api, notDummy, u.ZoneProgramID)
	}
}

func bindIfSet(api frontend.API, notDummy, field, public frontend.Variable) {
	isSet := api.Sub(1, api.IsZero(field))
	assertEqualWhen(api, api.Mul(notDummy, isSet), field, public)
}

func requireIdWhenDataSet(api frontend.API, notDummy, dataHash, id frontend.Variable) {
	dataIsSet := api.Sub(1, api.IsZero(dataHash))
	assertZeroWhen(api, api.Mul(notDummy, dataIsSet), api.IsZero(id))
}

// constrainInput verifies one input slot. A real spend (IsDummy == 0) runs
// domain, state-tree inclusion, owner binding, nullifier derivation, and
// nullifier-tree non-inclusion. A dummy slot (IsDummy == 1) is one of two kinds,
// selected by whether it carries a program_data_hash seed: a padding dummy is
// inert (owner 0, nullifier unpinned), while an address dummy skips inclusion and
// owner binding but binds owner == program_id, pins every non-seed field, and
// constrains its nullifier as the new program-owned address. It returns the
// input's UTXO hash (0 for any dummy) for the input transaction-hash chain, plus
// the address-chain contribution (the UTXO hash for an address slot, 0 otherwise).
func constrainInput(api frontend.API, in Input, nullifierPk frontend.Variable, env spendEnv) (frontend.Variable, frontend.Variable) {
	api.AssertIsBoolean(in.IsDummy)
	notDummy := api.Sub(1, in.IsDummy)

	// A dummy slot splits in two by whether it carries a program_data_hash (the
	// address seed). A padding dummy (seed == 0) is inert. An address dummy (seed
	// != 0) does not spend a prior commitment, but its nullifier is the new
	// program-owned address: derived, constrained, and inserted into the nullifier
	// tree, which enforces global uniqueness.
	dataIsSet := api.Sub(1, api.IsZero(in.Utxo.DataHash))
	isAddress := api.Mul(in.IsDummy, dataIsSet)
	isPadding := api.Sub(in.IsDummy, isAddress)
	spendOrAddress := api.Sub(1, isPadding)

	// A real input is program-owned when its owner equals the public program_id
	// (the authenticated CPI caller); the cpi_signer authorizes it out of circuit,
	// so it takes no user signature. A real input with any other owner is
	// user-owned and takes the signature path.
	programSet := api.Sub(1, api.IsZero(env.programID))
	ownerIsProgram := api.IsZero(api.Sub(in.Utxo.Owner, env.programID))
	isProgramOwned := api.Mul(notDummy, api.Mul(ownerIsProgram, programSet))
	userOwnedReal := api.Sub(notDummy, isProgramOwned)

	// A dummy slot must be inert: zero amount. A padding dummy's public transcript
	// columns (nullifier, roots, owner entry) are deliberately unpinned so it can
	// mimic a real slot and hide the transaction's real arity; the on-chain
	// reconstruction decides what values it accepts there. A padding owner is 0:
	// permanently unspendable, never a real spend.
	assertZeroWhen(api, in.IsDummy, in.Utxo.Amount)
	assertZeroWhen(api, isPadding, in.Utxo.Owner)

	// An address is owned by the authenticated invoking program: SPP sets the
	// public program_id from the CPI caller, so only that program can mint an
	// address in its own namespace. program_id must be set (a direct user call
	// leaves it 0 and cannot form an address).
	assertEqualWhen(api, isAddress, in.Utxo.Owner, env.programID)
	assertZeroWhen(api, isAddress, api.IsZero(env.programID))

	// The address must be a deterministic function of (program_id, seed) so one
	// pair yields exactly one address. Pin every field that is not the program id
	// (carried in Owner) or the seed (carried in DataHash).
	assertZeroWhen(api, isAddress, in.Utxo.Blinding)
	assertZeroWhen(api, isAddress, in.NullifierSecret)
	assertZeroWhen(api, isAddress, in.Utxo.Asset)
	assertZeroWhen(api, isAddress, in.Utxo.ZoneDataHash)
	assertZeroWhen(api, isAddress, in.Utxo.ZoneProgramID)

	// Program-owned spend: no user nullifier secret, and the public owner tag
	// equals the program. Authorization is the cpi_signer, checked by SPP.
	assertZeroWhen(api, isProgramOwned, in.NullifierSecret)
	assertEqualWhen(api, isProgramOwned, in.OwnerPkHash, env.programID)

	// Program data lives only on program-owned UTXOs and on the address seed; a
	// user-owned spend carries none. Program identity is the owner, so the
	// standalone program_id field is unused -- pin it to 0 on every real and
	// address slot.
	assertZeroWhen(api, userOwnedReal, in.Utxo.DataHash)
	assertZeroWhen(api, spendOrAddress, in.Utxo.ProgramID)

	// Domain is pinned for real spends and address slots alike (a padding dummy
	// leaves it free); spendOrAddress covers both.
	assertEqualWhen(api, spendOrAddress, in.Utxo.Domain, UtxoDomain)
	constrainProgramZone(api, notDummy, in.Utxo, env.zone, env.zoneAuthority, env.zoneProgramID)

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

	// Owner check: select the input's path and bind the owner. Anonymous routes on
	// the 0 sentinel — 0 binds to the shared P256 key (substituted via Select),
	// non-zero to the entry. Confidential routes by equality to the public
	// p256SigningPkField, so a P256 owner's pk_field is public in OwnerPkHash and is
	// already the owner key — no substitution, so the Select is omitted.
	var isP256, ownerKeyHash frontend.Variable
	if env.confidential {
		isP256 = api.IsZero(api.Sub(in.OwnerPkHash, env.p256SigningPkField))
		ownerKeyHash = in.OwnerPkHash
	} else {
		isP256 = api.IsZero(in.OwnerPkHash)
		ownerKeyHash = api.Select(isP256, env.p256PkField, in.OwnerPkHash)
	}
	if !env.requiresP256 {
		// Solana-only variant: the P256 gadget (incl. the signature check) is
		// absent, so every user-owned input MUST be Solana-owned. Otherwise the owner
		// key is the P256 path and p256SigValid is forced 1, which would let a UTXO
		// crafted for that owner be spent here with no signature.
		assertZeroWhen(api, userOwnedReal, isP256)
	}
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: ownerKeyHash,
		NullifierPk:  nullifierPk,
	})
	// Owner binding and the signature check apply to user-owned spends only. A
	// program-owned spend (owner == program_id) is authorized by the cpi_signer, so
	// it binds no owner hash and needs no signature.
	assertEqualWhen(api, userOwnedReal, ownerHash, in.Utxo.Owner)
	assertZeroWhen(api, api.Mul(userOwnedReal, isP256), api.Sub(1, env.p256SigValid))

	// Nullifier: Poseidon over the UTXO hash, blinding, and the input's own
	// secret — a canonical field element, inserted into the nullifier tree
	// untruncated. Constrained for real spends and address slots; a padding dummy
	// leaves it unpinned.
	nullifier := abstractor.Call(api, NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: in.NullifierSecret,
	})
	assertEqualWhen(api, spendOrAddress, nullifier, in.Nullifier)

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

	inputHash := api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
	addressHash := api.Select(isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

// assertDistinctNullifiers rejects two slots that insert the same nullifier in
// one transaction. The check is unconditional over every input: real spends and
// address slots carry pinned nullifiers that must differ (no double-spend, no
// duplicate address), and a padding dummy's nullifier is inserted on-chain too,
// so a collision would self-revert there -- failing here instead is fail-fast.
// Distinct random values stay indistinguishable from real nullifiers, so arity
// hiding is preserved.
func (c *Circuit) assertDistinctNullifiers(api frontend.API) {
	for i := range c.Inputs {
		for j := i + 1; j < len(c.Inputs); j++ {
			api.AssertIsDifferent(c.Inputs[i].Nullifier, c.Inputs[j].Nullifier)
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
