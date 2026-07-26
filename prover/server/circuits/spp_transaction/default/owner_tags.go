package defaultzone

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Owner-tag bindings are default-zone only: the default zone is the
// confidential zone, so its rails publish per-slot owner tags and must bind
// them. The anonymous custom-zone rails publish no output tags and authorize
// data outputs against private signer owners instead.

// AssertOutputOwnerTags — every real output's owner_hash must recompute from
// its public owner tag and the witnessed nullifier pubkey, which is what makes
// the tag usable as the output's signer identity. Dummy slots skip the binding
// so their tag stays free (see AssertDummyTags for what constrains it).
func AssertOutputOwnerTags(
	api frontend.API,
	outputs []shared.UtxoCircuitFields,
	ownerPkHashes []frontend.Variable,
	nullifierPks []frontend.Variable,
) error {
	if err := shared.ValidateLength("output owner pk hash", len(ownerPkHashes), len(outputs)); err != nil {
		return err
	}
	if err := shared.ValidateLength("output nullifier pk", len(nullifierPks), len(outputs)); err != nil {
		return err
	}
	for i, utxo := range outputs {
		ownerHash := gadget.PoseidonHash(api, []frontend.Variable{ownerPkHashes[i], nullifierPks[i]})
		shared.AssertWhen(api, isUtxo(api, utxo), api.IsZero(api.Sub(ownerHash, utxo.Owner)))
	}
	return nil
}

// AssertDummyTags constrains every dummy slot's public owner tag to name a
// transaction participant (a signer or the fee payer). A pad slot must be
// indistinguishable from a real one, so its tag stays a free choice — but an
// unconstrained tag lets the prover attribute the transaction to a third
// party (a victim's pk_field in a dummy input reads as their spend, in a
// dummy output as a payment to them). Self-attribution is always available
// (change outputs and the payer look exactly like this), so the constraint
// costs no privacy. Rails that publish no tags for a side pass nil.
func AssertDummyTags(
	api frontend.API,
	inputs []shared.Input,
	outputs []shared.UtxoCircuitFields,
	inputOwnerPkHashes []frontend.Variable,
	outputOwnerPkHashes []frontend.Variable,
	signers shared.Signers,
	payerPkHash frontend.Variable,
) error {
	if inputOwnerPkHashes != nil {
		if err := shared.ValidateLength("input owner pk hash", len(inputOwnerPkHashes), len(inputs)); err != nil {
			return err
		}
		for i, in := range inputs {
			participant := containsOrPayer(api, signers, inputOwnerPkHashes[i], payerPkHash)
			shared.AssertWhen(api, isDummy(api, in.Utxo), participant)
		}
	}
	if outputOwnerPkHashes != nil {
		if err := shared.ValidateLength("output owner pk hash", len(outputOwnerPkHashes), len(outputs)); err != nil {
			return err
		}
		for i, utxo := range outputs {
			participant := containsOrPayer(api, signers, outputOwnerPkHashes[i], payerPkHash)
			shared.AssertWhen(api, isDummy(api, utxo), participant)
		}
	}
	return nil
}

// containsOrPayer returns 1 iff identity is non-zero and names a transaction
// participant: a signer or the fee payer (who signed the transaction
// program-side).
func containsOrPayer(
	api frontend.API,
	signers shared.Signers,
	identity, payerPkHash frontend.Variable,
) frontend.Variable {
	notParticipant := api.Mul(
		api.Sub(1, signers.Contains(api, identity)),
		api.Sub(1, api.IsZero(api.Sub(identity, payerPkHash))),
	)
	return api.Mul(api.Sub(1, notParticipant), api.Sub(1, api.IsZero(identity)))
}

func isUtxo(api frontend.API, utxo shared.UtxoCircuitFields) frontend.Variable {
	return api.IsZero(api.Sub(utxo.Domain, shared.UtxoDomain))
}

func isDummy(api frontend.API, utxo shared.UtxoCircuitFields) frontend.Variable {
	return api.IsZero(api.Sub(utxo.Domain, shared.DummyDomain))
}
