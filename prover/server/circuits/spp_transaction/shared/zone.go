package shared

import "github.com/consensys/gnark/frontend"

// AssertInDefaultZone — default zone: no utxo may be a member of a zone.
func AssertInDefaultZone(api frontend.API, inputs []Input, outputs []UtxoCircuitFields) {
	for _, in := range inputs {
		in.Utxo.assertInDefaultZone(api)
	}
	for _, utxo := range outputs {
		utxo.assertInDefaultZone(api)
	}
}

// AssertZoneMemberOrFree — custom zone: every real utxo either belongs to the
// signing zone or to the default zone.
// Zone data requires a zone program.
func AssertZoneMemberOrFree(api frontend.API, inputs []Input, outputs []UtxoCircuitFields, zoneProgramID frontend.Variable) {
	assertZoneMembership(api, inputs, outputs, zoneProgramID, true)
}

// AssertZoneMember — zone authority: every real utxo belongs to the signing
// zone, with no exemption, so value cannot leave the zone on this rail.
func AssertZoneMember(api frontend.API, inputs []Input, outputs []UtxoCircuitFields, zoneProgramID frontend.Variable) {
	assertZoneMembership(api, inputs, outputs, zoneProgramID, false)
}

func assertZoneMembership(
	api frontend.API,
	inputs []Input,
	outputs []UtxoCircuitFields,
	zoneProgramID frontend.Variable,
	allowDefaultZone bool,
) {
	for _, in := range inputs {
		AssertWhen(api, in.isUtxo(api), checkZoneMembership(api, in.Utxo, zoneProgramID, allowDefaultZone))
	}
	for _, utxo := range outputs {
		AssertWhen(api, utxo.isUtxo(api), checkZoneMembership(api, utxo, zoneProgramID, allowDefaultZone))
	}
}

// checkZoneMembership returns 1 iff the utxo is owned by the signing zone.
// When allowDefaultZone is set, a default-zone utxo is also accepted, provided
// it has no zone data.
func checkZoneMembership(
	api frontend.API,
	u UtxoCircuitFields,
	zoneProgramID frontend.Variable,
	allowDefaultZone bool,
) frontend.Variable {
	isMemberOfSigningZone := api.IsZero(api.Sub(u.ZoneProgramID, zoneProgramID))
	if !allowDefaultZone {
		return isMemberOfSigningZone
	}

	inCustomZone := api.Sub(1, api.IsZero(u.ZoneProgramID))
	dataSet := api.Sub(1, api.IsZero(u.ZoneDataHash))
	// If it is in custom zone it must be member of signing zone.
	ok := api.Select(inCustomZone, isMemberOfSigningZone, frontend.Variable(1))
	// Data must only be set if it is in custom zone.
	return api.Mul(ok, api.Select(dataSet, inCustomZone, frontend.Variable(1)))
}
