package gnarksdk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// UtxoRead proves a UTXO is unspent without spending it: its hash is a leaf of
// the state tree and its nullifier is absent from the nullifier tree. The
// field names are the keys zolana-gnark-ffi-prover's utxo_read_proof_inputs
// writes.
//
// The proof is sound only together with the program's checks, which
// zolana_program::compression::ReadRoots performs:
//  1. both roots come from the shielded pool tree account's root histories,
//  2. the nullifier PDA of the nullifier on that tree does not exist.
//
// Non-inclusion alone misses a nullifier that is queued but not yet in the
// nullifier tree; the PDA check covers it. A nullifier PDA closes only once
// every root in the history contains its nullifier, so the two together cover
// every spend.
//
// The program derives the nullifier PDA, so the nullifier is public. A read
// publishes the nullifier the UTXO's spend reveals later, which links the read
// to the spend and repeated reads to each other.
type UtxoRead struct {
	StatePathElements [spp.StateTreeHeight]frontend.Variable
	StatePathIndex    frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements [spp.NullifierTreeHeight]frontend.Variable
	NullifierLowPathIndex    frontend.Variable
}

// Assert proves utxoHash is in the state tree at utxoRoot and nullifier is
// absent from the nullifier tree at nullifierRoot.
func (r UtxoRead) Assert(api frontend.API, utxoHash, utxoRoot, nullifier, nullifierRoot frontend.Variable) {
	stateRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  api.ToBinary(r.StatePathIndex, spp.StateTreeHeight),
		Path:   r.StatePathElements[:],
		Height: spp.StateTreeHeight,
	})
	api.AssertIsEqual(stateRoot, utxoRoot)

	// The low leaf H(NullifierLowValue, NullifierNextValue) is in the nullifier
	// tree and brackets the nullifier over full field values.
	lowLeafHash := gadget.IndexedLeafHash(api, r.NullifierLowValue, r.NullifierNextValue)
	lowRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   lowLeafHash,
		Index:  api.ToBinary(r.NullifierLowPathIndex, spp.NullifierTreeHeight),
		Path:   r.NullifierLowPathElements[:],
		Height: spp.NullifierTreeHeight,
	})
	api.AssertIsEqual(lowRoot, nullifierRoot)
	abstractor.CallVoid(api, spp.AssertStrictlyOrdered{
		Lo:  r.NullifierLowValue,
		Mid: nullifier,
		Hi:  r.NullifierNextValue,
	})
}
