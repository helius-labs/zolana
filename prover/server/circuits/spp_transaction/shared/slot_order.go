package shared

import "github.com/consensys/gnark/frontend"

// AssertDummiesLast rejects a real slot after a dummy, so application proofs
// can map private tx hash entries to SPP slots (spec: Slot order).
// (d-AddressDomain)(d-UtxoDomain) is nonzero only for a dummy because
// constrainInput and ConstrainOutput already restrict d to the three domains.
func AssertDummiesLast(api frontend.API, utxos []UtxoCircuitFields) {
	for i := 1; i < len(utxos); i++ {
		previous := utxos[i-1].Domain
		previousIsNotReal := api.Mul(api.Sub(previous, AddressDomain), api.Sub(previous, UtxoDomain))
		api.AssertIsEqual(api.Mul(previousIsNotReal, api.Sub(utxos[i].Domain, DummyDomain)), 0)
	}
}
