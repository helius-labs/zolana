package squadsring

import (
	"github.com/consensys/gnark/frontend"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
	squadsutils "zolana/prover/circuits/squads/utils"
)

const p256ScalarLimbBits = 128

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
	SharedViewingSecretKey emulated.Element[emulated.P256Fr]
}

type ViewingKeyAccount struct {
	Public  PublicViewingKeyAccount
	Private PrivateViewingKeyAccount
}

func (a ViewingKeyAccount) Constrain(api frontend.API, tx squadsutils.Transaction, inputsDummy []frontend.Variable, outputIndex int) error {
	output := tx.Outputs[outputIndex]

	// Bind the account identity to both sides of the spend. The SPP ring-authority
	// proof proves only that the transaction has internally consistent owners.
	// This constraint makes that owner the ring-selected ViewingKeyAccount rather
	// than an unrelated account in the same ring.
	ownerHash := abstractor.Call(api, shared.OwnerHashGadget{
		OwnerKeyHash: a.Public.Owner,
		NullifierPk:  a.Public.NullifierPubkey,
	})
	api.AssertIsEqual(output.OwnerHash, ownerHash)
	api.AssertIsEqual(tx.Inputs[0].OwnerHash, ownerHash)
	for i, dummy := range inputsDummy {
		// InputsDummy[i] describes Inputs[i+1]. Padding inputs have owner 0 and are
		// deliberately excluded. Every real input must belong to the selected account.
		api.AssertIsEqual(
			api.Mul(api.Sub(1, dummy), api.Sub(tx.Inputs[i+1].OwnerHash, ownerHash)),
			0,
		)
	}

	return a.ConstrainPublicInputs(api)
}

func (a ViewingKeyAccount) ConstrainPublicInputs(api frontend.API) error {
	nullifierPubkey := gadget.PoseidonHash(api, []frontend.Variable{a.Private.NullifierSecret})
	api.AssertIsEqual(a.Public.NullifierPubkey, nullifierPubkey)

	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return err
	}
	skBits := fr.ToBitsCanonical(&a.Private.SharedViewingSecretKey)
	skLow := gnarkbits.FromBinary(api, skBits[:p256ScalarLimbBits])
	skHigh := gnarkbits.FromBinary(api, skBits[p256ScalarLimbBits:])
	commitment := gadget.PoseidonHash(api, []frontend.Variable{skLow, skHigh})
	api.AssertIsEqual(a.Public.SharedViewingSecretKeyCommitment, commitment)
	return nil
}
