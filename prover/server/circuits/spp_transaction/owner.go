package transaction

import (
	gadgetlib "light/light-prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
)

// OwnerHashGadget binds an owner key hash to a nullifier public key.
type OwnerHashGadget struct {
	OwnerKeyHash frontend.Variable
	NullifierPk  frontend.Variable
}

func (gadget OwnerHashGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.OwnerKeyHash, gadget.NullifierPk})
}
