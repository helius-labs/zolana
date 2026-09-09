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

// AssertPublishedOutputOwners binds the public masked owner vector used by
// owner-signed custom-ring rails. A real default-ring output publishes its
// actual private owner identity; a real policy-ring output must publish zero.
// Dummy slots are handled separately so they may choose either marker.
func AssertPublishedOutputOwners(
	api frontend.API,
	outputs []UtxoCircuitFields,
	ownerPkHashes []frontend.Variable,
	publishedOwnerPkHashes []frontend.Variable,
) error {
	if err := ValidateLength("output owner pk hash", len(ownerPkHashes), len(outputs)); err != nil {
		return err
	}
	if err := ValidateLength("published output owner pk hash", len(publishedOwnerPkHashes), len(outputs)); err != nil {
		return err
	}
	for i, utxo := range outputs {
		isReal := utxo.isUtxo(api)
		isDefaultRing := api.IsZero(utxo.RingProgramID)
		expected := api.Mul(isDefaultRing, ownerPkHashes[i])
		AssertWhen(api, isReal, api.IsZero(api.Sub(publishedOwnerPkHashes[i], expected)))
	}
	return nil
}

// AssertMaskedDummyOutputTags constrains the published tag of every dummy
// output. Zero is always allowed: a real policy-ring output publishes zero, so
// a zero dummy hides among them. A non-zero tag must repeat an identity this
// transaction already publishes: an entry of publicIdentities or a real
// output's published owner. Every entry of publicIdentities must itself be a
// public input, which is what makes a dummy tag unable to disclose a private
// identity such as a policy-ring recipient or the shared P256 owner during a
// ring spend. See AssertDummyTags for why the payer is not a nameable identity.
func AssertMaskedDummyOutputTags(
	api frontend.API,
	outputs []UtxoCircuitFields,
	publishedOwnerPkHashes []frontend.Variable,
	publicIdentities Signers,
) error {
	if err := ValidateLength("published output owner pk hash", len(publishedOwnerPkHashes), len(outputs)); err != nil {
		return err
	}
	participants := append(Signers(nil), publicIdentities...)
	for i, utxo := range outputs {
		participants = append(participants, api.Mul(utxo.isUtxo(api), publishedOwnerPkHashes[i]))
	}
	for i, utxo := range outputs {
		isPublished := api.Sub(1, api.IsZero(publishedOwnerPkHashes[i]))
		AssertWhen(
			api,
			api.Mul(utxo.isDummy(api), isPublished),
			participants.Contains(api, publishedOwnerPkHashes[i]),
		)
	}
	return nil
}

// AssertDummyTags constrains every dummy slot's public owner tag to name a
// transaction participant: an owner signer other than the payer, or a real
// output owner. A pad slot must be indistinguishable from a real one, so its
// tag stays a free choice — but an unconstrained tag lets the prover attribute
// the transaction to a third party (a victim's pk_field in a dummy input reads
// as their spend, in a dummy output as a payment to them). Self-attribution is
// always available (change and recipient outputs look exactly like this), so
// the constraint costs no privacy. The payer is excluded because a fee sponsor
// signs without taking part in the shielded transfer and must not be shown as
// a recipient; a self-paying owner is still nameable through the tag of its
// own change output, and a wallet that pads a self-paid transaction without
// change emits a zero-amount change output instead of a dummy. Callers pass
// the signer vector without the payer; rails that publish no tags for a side
// pass nil.
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
