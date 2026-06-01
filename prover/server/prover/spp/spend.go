package spp

import "github.com/consensys/gnark/frontend"

// spendEnv holds values shared by every input-spend check. They are computed
// once per proof from the wallet secret and the single P256 signer.
type spendEnv struct {
	nullifierPkFromSecret frontend.Variable
	p256OwnerKeyHash      frontend.Variable
	p256SigValid          frontend.Variable
	nullifierSecret       frontend.Variable
}

// constrainInput verifies one spent input: domain, state-tree inclusion, owner
// binding, nullifier derivation, and nullifier-tree non-inclusion. It returns
// the input's UTXO hash (0 for a dummy) for the transaction-hash chain.
func constrainInput(api frontend.API, in Input, env spendEnv) frontend.Variable {
	api.AssertIsBoolean(in.IsDummy)
	notDummy := api.Sub(1, in.IsDummy)

	assertZeroWhen(api, in.IsDummy, in.Utxo.AssetAmount)
	assertEqualWhen(api, notDummy, in.Utxo.Domain, UtxoDomain) // pin domain

	utxoHash := UtxoHashCircuit(api, in.Utxo)

	// Inclusion: utxoHash is a leaf of the state tree at UtxoTreeRoot.
	stateRoot := StatePathFoldCircuit(api, utxoHash, in.State.Siblings, in.State.Directions)
	assertEqualWhen(api, notDummy, stateRoot, in.UtxoTreeRoot)

	// Owner check: P256 inputs (SolanaPkHash == 0) rebuild the owner key hash
	// from the P256 point in the witness; Solana inputs use the public hash.
	isP256 := api.IsZero(in.SolanaPkHash)
	ownerKeyHash := api.Select(isP256, env.p256OwnerKeyHash, in.SolanaPkHash)
	ownerHash := OwnerHashCircuit(api, ownerKeyHash, in.NullifierPk)
	assertEqualWhen(api, notDummy, ownerHash, in.Utxo.Owner)
	assertEqualWhen(api, notDummy, env.nullifierPkFromSecret, in.NullifierPk)
	// Real P256 inputs must carry a valid signature; Solana inputs are verified
	// by SPP out of circuit.
	assertZeroWhen(api, api.Mul(notDummy, isP256), api.Sub(1, env.p256SigValid))
	assertZeroWhen(api, in.IsDummy, in.NullifierPk)
	assertZeroWhen(api, in.IsDummy, in.SolanaPkHash)

	// Nullifier: derived from the UTXO hash, blinding, and shared secret.
	nullifier := NullifierHashCircuit(api, utxoHash, in.Utxo.Blinding, env.nullifierSecret)
	assertEqualWhen(api, notDummy, nullifier, in.Nullifier)
	assertZeroWhen(api, in.IsDummy, in.Nullifier)

	// Non-inclusion: the low leaf is in the nullifier tree and brackets the
	// nullifier (NfLowValue < Nullifier < NfNextValue).
	lowLeaf := IndexedLeafHashCircuit(api, in.NfLowValue, in.NfNextValue)
	nfRoot := StatePathFoldCircuit(api, lowLeaf, in.NfLow.Siblings, in.NfLow.Directions)
	assertEqualWhen(api, notDummy, nfRoot, in.NullifierRoot)
	assertStrictlyOrdered(api, in.IsDummy, in.NfLowValue, in.Nullifier, in.NfNextValue)

	return api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
}

// constrainOutput verifies one created output and returns its UTXO hash (0 for a
// dummy) for the transaction-hash chain.
func constrainOutput(api frontend.API, out Output) frontend.Variable {
	api.AssertIsBoolean(out.IsDummy)
	notDummy := api.Sub(1, out.IsDummy)

	assertZeroWhen(api, out.IsDummy, out.Utxo.AssetAmount)
	assertEqualWhen(api, notDummy, out.Utxo.Domain, UtxoDomain) // pin domain

	utxoHash := UtxoHashCircuit(api, out.Utxo)
	assertEqualWhen(api, notDummy, utxoHash, out.Hash)
	assertZeroWhen(api, out.IsDummy, out.Hash)

	return api.Select(out.IsDummy, frontend.Variable(0), utxoHash)
}

// assertDistinctNullifiers rejects spending the same input twice in one
// transaction: every pair of real inputs must carry distinct nullifiers. Dummy
// inputs all carry nullifier 0 and are excluded.
func (c *Circuit) assertDistinctNullifiers(api frontend.API) {
	for i := range c.Inputs {
		for j := i + 1; j < len(c.Inputs); j++ {
			bothReal := api.Mul(api.Sub(1, c.Inputs[i].IsDummy), api.Sub(1, c.Inputs[j].IsDummy))
			sameNullifier := api.IsZero(api.Sub(c.Inputs[i].Nullifier, c.Inputs[j].Nullifier))
			api.AssertIsEqual(api.Mul(bothReal, sameNullifier), 0)
		}
	}
}
