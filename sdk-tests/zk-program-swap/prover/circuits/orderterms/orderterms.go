package orderterms

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
)

const TakeModeDerived uint64 = 0
const TakeModeVerifiable uint64 = 1

const TakeEncKdfDomain uint64 = 0x5357_4150_5441_4b45

type OrderTerms struct {
	DestinationAsset  frontend.Variable
	DestinationAmount frontend.Variable
	MakerOwnerHash    frontend.Variable
	MakerViewingPk    [33]frontend.Variable
	Expiry            frontend.Variable
	TakerPkFe         frontend.Variable
	TakeMode          frontend.Variable
}

func (o OrderTerms) Check(api frontend.API) {
	api.AssertIsDifferent(o.DestinationAmount, 0)
	api.ToBinary(o.DestinationAmount, 64)
	api.AssertIsBoolean(o.TakeMode)
}

func (o OrderTerms) MakerAddressFE(api frontend.API) frontend.Variable {
	lo, hi := ve.Pack33To2FECircuit(api, o.MakerViewingPk)
	return gadget.PoseidonHash(api, []frontend.Variable{o.MakerOwnerHash, lo, hi})
}

func (o OrderTerms) DataHash(api frontend.API, makerAddressFe frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		o.DestinationAsset,
		o.DestinationAmount,
		makerAddressFe,
		o.Expiry,
		o.TakerPkFe,
		o.TakeMode,
	})
}
