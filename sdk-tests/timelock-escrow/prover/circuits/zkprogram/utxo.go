package zkprogram

import (
	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
)

type State interface {
	DataHash(api frontend.API) frontend.Variable
}

func ProgramOutput[S State](api frontend.API, owner frontend.Variable, state S, asset, amount frontend.Variable) Output {
	return Output{Owner: owner, Asset: asset, Amount: amount, DataHash: state.DataHash(api)}
}

type ProgramUtxo[S State] struct {
	Utxo  gnarksdk.Utxo
	State S
}

func (p ProgramUtxo[S]) Hash(api frontend.API) InputHash {
	p.Utxo.AssertDefaultRing(api)
	api.AssertIsEqual(p.Utxo.DataHash, p.State.DataHash(api))
	return InputHash{value: p.Utxo.Hash(api)}
}

func PlainHash(api frontend.API, utxo gnarksdk.Utxo) InputHash {
	utxo.AssertDefaultRing(api)
	api.AssertIsEqual(utxo.DataHash, 0)
	return InputHash{value: utxo.Hash(api)}
}
