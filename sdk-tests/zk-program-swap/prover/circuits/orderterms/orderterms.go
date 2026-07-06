package orderterms

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
)

const FillModeDerived uint64 = 3
const FillModeVerifiable uint64 = 5

const FillEncKdfDomain uint64 = 0x5357_4150_4649_4c4c

func MakerAddressFE(api frontend.API, ownerHash frontend.Variable, viewingPk [33]frontend.Variable) frontend.Variable {
	lo, hi := ve.Pack33To2FECircuit(api, viewingPk)
	return gadget.PoseidonHash(api, []frontend.Variable{ownerHash, lo, hi})
}
