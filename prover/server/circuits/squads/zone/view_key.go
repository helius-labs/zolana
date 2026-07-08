package squadszone

import (
	"github.com/consensys/gnark/frontend"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction"
	zoneutils "zolana/prover/circuits/zone-utils"
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

func (a ViewingKeyAccount) Constrain(api frontend.API, tx zoneutils.Transaction, outputIndex int) error {
	output := tx.Outputs[outputIndex]

	// Check owner is correct
	ownerHash := abstractor.Call(api, transaction.OwnerHashGadget{
		OwnerKeyHash: a.Public.Owner,
		NullifierPk:  a.Public.NullifierPubkey,
	})
	api.AssertIsEqual(output.OwnerHash, ownerHash)

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
