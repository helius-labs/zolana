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
	// addressTreePubkeyField is sha256_be(address_tree_pubkey) as a single field
	// element, fed into AddressGadget for address-slot derivation. The per-program
	// namespacing reuses programID, so no separate program-id input is needed.
	addressTreePubkeyField frontend.Variable
}

// constrainInput verifies one input slot. It classifies the slot, then applies
// the per-kind constraints; every check is gated by a selector, so a constraint
// is inert for the kinds it does not apply to. It returns the input's UTXO hash
// (0 for any dummy) for the input transaction-hash chain, plus the address-chain
// contribution (the UTXO hash for an address slot, 0 otherwise).
func constrainInput(api frontend.API, in Input, nullifierPk frontend.Variable, env spendEnv) (frontend.Variable, frontend.Variable) {
	k := slotSelectors(api, in, env)
	constrainDummyInput(api, k, in)
	constrainAddressSlot(api, k, &in, env)
	constrainProgramData(api, k, in, env)
	constrainOwnerBinding(api, k, in, nullifierPk, env)
	utxoHash := constrainCommitmentAndTrees(api, k, in, env)

	inputHash := api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
	addressHash := api.Select(k.isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

// slotKind holds the per-slot selector flags. A slot is a real spend
// (IsDummy == 0), an address-creation dummy (IsDummy == 1, seed != 0), or an
// inert padding dummy (IsDummy == 1, seed == 0). A real spend is further split
// into program-owned (owner == program_id) and user-owned.
type slotKind struct {
	isDummy frontend.Variable
	// notDummy       frontend.Variable
	isAddress frontend.Variable
	// isDummyOrAddress frontend.Variable
	// spendOrAddress frontend.Variable
	isProgramOwned frontend.Variable
	isUserOwned    frontend.Variable
}

// slotSelectors derives the slot's kind flags from IsDummy, the program_data
// seed, and the public program_id.
func slotSelectors(api frontend.API, in Input, env spendEnv) slotKind {
	api.AssertIsBoolean(in.IsDummy)
	api.AssertIsBoolean(in.IsAddress)
	assertZeroWhen(api, in.IsAddress, api.IsZero(in.IsDummy))
	notDummy := api.Sub(1, in.IsDummy)
	// Program owned:
	// 1. program data, and assert that program id must match.
	isOwned := api.Sub(1, api.IsZero(in.Utxo.Owner))
	isProgramOwned := api.Sub(1, api.IsZero(in.Utxo.DataHash))
	// Must be set if program owned.
	// programSet := api.Sub(1, api.IsZero(env.programID))
	assertZeroWhen(api, isProgramOwned, programSet)

	isUserOwned :=  api.Sub(isOwned, isProgramOwned),

	return slotKind{
		isDummy: in.IsDummy,
		// notDummy:       notDummy,
		isAddress: in.IsAddress,
		// isDummyOrAddress: isDummyOrAddress,
		//	spendOrAddress: api.Sub(1, isPadding),
		isProgramOwned: isProgramOwned,
		isUserOwned:    isUserOwned,
	}
}

// All zeroed when if address.
// All zeroed except blinding if dummy.
func constrainDummyInput(api frontend.API, k slotKind, in Input) {
	assertZeroWhen(api, k.isDummy, in.Utxo.Amount)
	assertZeroWhen(api, k.isDummy, in.Utxo.Domain)
	assertZeroWhen(api, k.isDummy, in.Utxo.Owner)
	assertZeroWhen(api, k.isDummy, in.Utxo.Asset)
	assertZeroWhen(api, k.isDummy, in.Utxo.Address)
	assertZeroWhen(api, k.isDummy, in.Utxo.ZoneDataHash)
	assertZeroWhen(api, k.isDummy, in.Utxo.DataHash)
	assertZeroWhen(api, k.isDummy, in.Utxo.ZoneProgramID)
	assertZeroWhen(api, k.isDummy, in.NullifierSecret)
}

// 1. Program id must be non zero for address.
// 2. Address must equal nullifier.
func constrainAddressSlot(api frontend.API, k slotKind, in *Input, env spendEnv) {
	assertZeroWhen(api, k.isAddress, api.IsZero(env.programID))
	assertZeroWhen(api, k.isAddress, api.IsZero(in.AddressSeed))

	assertZeroWhen(api, k.isAddress, in.Utxo.Amount)
	assertZeroWhen(api, k.isAddress, in.Utxo.Domain)
	assertZeroWhen(api, k.isAddress, in.Utxo.Owner)
	assertZeroWhen(api, k.isAddress, in.Utxo.Asset)
	assertZeroWhen(api, k.isAddress, in.Utxo.Address)
	assertZeroWhen(api, k.isAddress, in.Utxo.ZoneDataHash)
	assertZeroWhen(api, k.isAddress, in.Utxo.DataHash)
	assertZeroWhen(api, k.isAddress, in.Utxo.ZoneProgramID)
	assertZeroWhen(api, k.isAddress, in.NullifierSecret)
	assertZeroWhen(api, k.isAddress, in.Utxo.Blinding)

	derivedAddress := abstractor.Call(api, AddressGadget{
		ProgramId:  env.programID,
		TreePubkey: env.addressTreePubkeyField,
		Seed:       in.AddressSeed,
	})
	in.Utxo.Address = api.Select(k.isAddress, derivedAddress, in.Utxo.Address)
	assertEqualWhen(api, k.isAddress, derivedAddress, in.Nullifier)
}

// constrainProgramZone binds a UTXO's zone fields. The program-data/address
// binding lives in the callers: program identity is the owner, and program data
// plus a non-zero Address are allowed only on program-owned UTXOs and address
// slots (see constrainInput / constrainOutput).
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


// constrainProgramData enforces who may carry program data and an address.
// Program data and a non-zero Address live only on program-owned UTXOs (the
// address on address slots is handled in constrainAddressSlot): a user-owned
// spend and a padding dummy carry neither. A program-owned spend pins
// nullifier_secret = 0 and binds its public owner tag to the program;
// authorization is the cpi_signer.
func constrainProgramOwned(api frontend.API, k slotKind, in Input, env spendEnv) {
	assertZeroWhen(api, k.isProgramOwned, in.NullifierSecret)
	assertEqualWhen(api, k.isProgramOwned, in.OwnerPkHash, env.programID)

	assertZeroWhen(api, k.isUserOwned, in.Utxo.DataHash)
	assertZeroWhen(api, k.isUserOwned, in.Utxo.Address)
}

func constrainUserOwned(api frontend.API, k slotKind, in Input, env spendEnv) {
	assertZeroWhen(api, k.isProgramOwned, in.NullifierSecret)
	assertEqualWhen(api, k.isProgramOwned, in.OwnerPkHash, env.programID)

	assertZeroWhen(api, k.isUserOwned, in.Utxo.DataHash)
	assertZeroWhen(api, k.isUserOwned, in.Utxo.Address)
}

// constrainOwnerBinding authorizes a user-owned spend: it selects the owner key
// path and binds the recomputed owner_hash to the UTXO owner, plus the P256
// signature when the owner is P256. Anonymous routes on the 0 sentinel (0 binds
// to the shared P256 key, substituted via Select); confidential routes by
// equality to the public p256SigningPkField, where the owner key is already in
// OwnerPkHash so no substitution is needed. A program-owned spend is authorized
// by the cpi_signer, so it binds no owner hash here.
func constrainOwnerBinding(api frontend.API, k slotKind, in Input, nullifierPk frontend.Variable, env spendEnv) {
	var isP256, ownerKeyHash frontend.Variable
	if env.confidential {
		isP256 = api.IsZero(api.Sub(in.OwnerPkHash, env.p256SigningPkField))
		ownerKeyHash = in.OwnerPkHash
	} else {
		isP256 = api.IsZero(in.OwnerPkHash)
		ownerKeyHash = api.Select(isP256, env.p256PkField, in.OwnerPkHash)
	}
	if !env.requiresP256 {
		// Solana-only variant: the P256 gadget (incl. the signature check) is absent,
		// so every user-owned input MUST be Solana-owned. Otherwise the owner key is
		// the P256 path and p256SigValid is forced 1, which would let a UTXO crafted
		// for that owner be spent here with no signature.
		assertZeroWhen(api, k.isUserOwned, isP256)
	}
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: ownerKeyHash,
		NullifierPk:  nullifierPk,
	})
	assertEqualWhen(api, k.isUserOwned, ownerHash, in.Utxo.Owner)
	assertZeroWhen(api, api.Mul(k.isUserOwned, isP256), api.Sub(1, env.p256SigValid))
}

// constrainCommitmentAndTrees pins the domain and zone fields, computes the UTXO
// hash, and runs the real-spend tree proofs: state-tree inclusion, the spend
// nullifier, and nullifier-tree non-inclusion. Inclusion, the nullifier binding,
// and non-inclusion are gated to real spends; the domain is pinned for address
// slots too (a padding dummy leaves it free). Returns the UTXO hash.
func constrainCommitmentAndTrees(api frontend.API, k slotKind, in Input, env spendEnv) frontend.Variable {
	assertEqualWhen(api, k.spendOrAddress, in.Utxo.Domain, UtxoDomain)
	constrainProgramZone(api, k.notDummy, in.Utxo, env.zone, env.zoneAuthority, env.zoneProgramID)

	utxoHash := UtxoHashCircuit(api, in.Utxo)

	// Inclusion: utxoHash is a leaf of the state tree at UtxoTreeRoot.
	statePathIndices := api.ToBinary(in.StatePathIndex, StateTreeHeight)
	stateRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  statePathIndices,
		Path:   in.StatePathElements,
		Height: StateTreeHeight,
	})
	// Enforced if real.
	// Not enforced if address or dummy.
	assertEqualWhen(api, k.notDummy, stateRoot, in.UtxoTreeRoot)

	// Nullifier: a real spend nullifies its commitment via Poseidon over the UTXO
	// hash, blinding, and its own secret. An address slot's nullifier is bound in
	// constrainAddressSlot; a padding dummy leaves it unpinned.
	nullifier := abstractor.Call(api, NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: in.NullifierSecret,
	})
	// Enforced if real.
	// Not enforced if address or dummy.
	assertEqualWhen(api, k.notDummy, nullifier, in.Nullifier)

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
	assertEqualWhen(api, k.notDummy, nfRoot, in.NullifierTreeRoot)
	assertStrictlyOrdered(api, k.isDummy, in.NullifierLowValue, in.Nullifier, in.NullifierNextValue)

	return utxoHash
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
