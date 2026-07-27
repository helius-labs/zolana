package shared

import (
	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
)

// Owner-tag bindings apply to rails that publish per-slot owner tags. Rails
// that keep tags private skip the corresponding checks.

// AssertOutputOwnerTags — every real output's owner_hash must recompute from
// its public owner tag and the witnessed nullifier pubkey, which is what makes
// the tag usable as the output's signer identity. Dummy slots skip the binding
// so their tag stays free (see AssertDummyTags for what constrains it).
func AssertOutputOwnerTags(
	api frontend.API,
	outputs []UtxoCircuitFields,
	ownerPkHashes []frontend.Variable,
	nullifierPks []frontend.Variable,
) error {
	if err := ValidateLength("output owner pk hash", len(ownerPkHashes), len(outputs)); err != nil {
		return err
	}
	if err := ValidateLength("output nullifier pk", len(nullifierPks), len(outputs)); err != nil {
		return err
	}
	for i, utxo := range outputs {
		ownerHash := gadget.PoseidonHash(api, []frontend.Variable{ownerPkHashes[i], nullifierPks[i]})
		AssertWhen(api, utxo.isUtxo(api), api.IsZero(api.Sub(ownerHash, utxo.Owner)))
	}
	return nil
}

// AssertDummyTags constrains every dummy slot's public owner tag to name a
// transaction participant: a real input signer or a real output owner. A pad
// slot must be
// indistinguishable from a real one, so its tag stays a free choice — but an
// unconstrained tag lets the prover attribute the transaction to a third
// party (a victim's pk_field in a dummy input reads as their spend, in a
// dummy output as a payment to them). Self-attribution is always available
// (change and recipient outputs look exactly like this), so the constraint
// costs no privacy. Rails that publish no tags for a side pass nil.
func AssertDummyTags(
	api frontend.API,
	inputs []Input,
	outputs []UtxoCircuitFields,
	inputOwnerPkHashes []frontend.Variable,
	outputOwnerPkHashes []frontend.Variable,
	signers Signers,
) error {
	participants := append(Signers(nil), signers...)
	if outputOwnerPkHashes != nil {
		if err := ValidateLength("output owner pk hash", len(outputOwnerPkHashes), len(outputs)); err != nil {
			return err
		}
		for i, utxo := range outputs {
			// A dummy output cannot introduce a participant by naming itself.
			participants = append(participants, api.Mul(utxo.isUtxo(api), outputOwnerPkHashes[i]))
		}
	}

	if inputOwnerPkHashes != nil {
		if err := ValidateLength("input owner pk hash", len(inputOwnerPkHashes), len(inputs)); err != nil {
			return err
		}
		for i, in := range inputs {
			AssertWhen(api, in.isDummy(api), participants.Contains(api, inputOwnerPkHashes[i]))
		}
	}
	if outputOwnerPkHashes != nil {
		for i, utxo := range outputs {
			AssertWhen(api, utxo.isDummy(api), participants.Contains(api, outputOwnerPkHashes[i]))
		}
	}
	return nil
}
