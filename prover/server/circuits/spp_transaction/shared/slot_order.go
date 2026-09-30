package shared

import "github.com/consensys/gnark/frontend"

func AssertDummiesLast(api frontend.API, utxos []UtxoCircuitFields) {
	for i := 1; i < len(utxos); i++ {
		previous := utxos[i-1].Domain
		previousIsNotReal := api.Mul(api.Sub(previous, AddressDomain), api.Sub(previous, UtxoDomain))
		api.AssertIsEqual(api.Mul(previousIsNotReal, api.Sub(utxos[i].Domain, DummyDomain)), 0)
	}
}
