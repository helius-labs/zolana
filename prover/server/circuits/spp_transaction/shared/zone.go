package shared

import "github.com/consensys/gnark/frontend"

// Each variant asserts its own zone rule over every utxo it touches, inputs and
// outputs alike, before handing the transaction to Transaction.Constrain, which
// knows nothing about zones. The rules differ in strictness, and each pairs with
// an assertion on the public ZoneProgramID that the variant makes itself
// (== 0 for the default zone, != 0 for the zone authority).

// AssertDefaultZone — default zone: no utxo may be a member of a zone, dummy
// slots included, so the zone fields are pinned to 0 across the transaction.
func AssertDefaultZone(api frontend.API, inputs []Input, outputs []UtxoCircuitFields) {
	for _, in := range inputs {
		in.Utxo.assertInDefaultZone(api)
	}
	for _, utxo := range outputs {
		utxo.assertInDefaultZone(api)
	}
}

// AssertZoneMemberOrFree — custom zone: every real utxo either belongs to the
// signing zone or to no zone at all, and zone data requires a zone program.
func AssertZoneMemberOrFree(api frontend.API, inputs []Input, outputs []UtxoCircuitFields, zoneProgramID frontend.Variable) {
	forEachRealUtxo(api, inputs, outputs, func(utxo UtxoCircuitFields) frontend.Variable {
		return checkZoneMemberOrFree(api, utxo, zoneProgramID)
	})
}

// AssertZoneMember — zone authority: every real utxo belongs to the signing
// zone, with no exemption, so value cannot leave the zone on this rail.
func AssertZoneMember(api frontend.API, inputs []Input, outputs []UtxoCircuitFields, zoneProgramID frontend.Variable) {
	forEachRealUtxo(api, inputs, outputs, func(utxo UtxoCircuitFields) frontend.Variable {
		return checkZoneMember(api, utxo, zoneProgramID)
	})
}

func forEachRealUtxo(
	api frontend.API,
	inputs []Input,
	outputs []UtxoCircuitFields,
	check func(UtxoCircuitFields) frontend.Variable,
) {
	for _, in := range inputs {
		assertWhen(api, in.IsUtxo(api), check(in.Utxo))
	}
	for _, utxo := range outputs {
		assertWhen(api, utxo.IsUtxo(api), check(utxo))
	}
}

// checkZoneMember returns 1 iff the utxo is owned by the public zone.
func checkZoneMember(api frontend.API, u UtxoCircuitFields, zoneProgramID frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(u.ZoneProgramID, zoneProgramID))
}

// checkZoneMemberOrFree returns 1 iff the utxo is owned by the signing zone or
// is not a member of any zone; zone data always needs a zone program.
func checkZoneMemberOrFree(api frontend.API, u UtxoCircuitFields, zoneProgramID frontend.Variable) frontend.Variable {
	inCustomZone := api.Sub(1, api.IsZero(u.ZoneProgramID))
	isMemberOfSigningZone := api.IsZero(api.Sub(u.ZoneProgramID, zoneProgramID))
	dataSet := api.Sub(1, api.IsZero(u.ZoneDataHash))
	// If it is in custom zone it must be member of signing zone.
	ok := api.Select(inCustomZone, isMemberOfSigningZone, frontend.Variable(1))
	// Data must only be set if it is in custom zone.
	return api.Mul(ok, api.Select(dataSet, inCustomZone, frontend.Variable(1)))
}
