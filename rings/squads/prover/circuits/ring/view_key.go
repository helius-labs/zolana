package squadsring

import (
	"github.com/consensys/gnark/frontend"

	"circuits/ringutils"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// ownerHash is the SPP owner_hash: Poseidon(owner_proof_input_hash, nullifier_pk).
// Owner is the account owner's proof input hash.
func ownerHash(api frontend.API, owner, nullifierPk frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{owner, nullifierPk})
}

type PublicViewingKeyAccount struct {
	Owner                            frontend.Variable
	SharedViewingSecretKeyCommitment frontend.Variable
	NullifierPubkey                  frontend.Variable
}

func (a PublicViewingKeyAccount) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		a.Owner,
		a.SharedViewingSecretKeyCommitment,
		a.NullifierPubkey,
	})
}

type PrivateViewingKeyAccount struct {
	NullifierSecret        frontend.Variable
	SharedViewingSecretKey [32]frontend.Variable
}

type ViewingKeyAccount struct {
	Public  PublicViewingKeyAccount
	Private PrivateViewingKeyAccount
}

func (a ViewingKeyAccount) Constrain(api frontend.API, tx ringutils.Transaction, outputIndex int) error {
	output := tx.Outputs[outputIndex]

	api.AssertIsEqual(output.OwnerHash, ownerHash(api, a.Public.Owner, a.Public.NullifierPubkey))

	return a.ConstrainPublicInputs(api)
}

func (a ViewingKeyAccount) ConstrainPublicInputs(api frontend.API) error {
	nullifierPubkey := gadget.PoseidonHash(api, []frontend.Variable{a.Private.NullifierSecret})
	api.AssertIsEqual(a.Public.NullifierPubkey, nullifierPubkey)

	commitment := ringutils.ViewingKeyCommitment(api, a.Private.SharedViewingSecretKey)
	api.AssertIsEqual(a.Public.SharedViewingSecretKeyCommitment, commitment)
	return nil
}
