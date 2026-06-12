package transaction

import (
	"light/light-prover/prover/poseidon"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark/frontend"
)

type UtxoCircuitFields struct {
	Domain        frontend.Variable
	Owner         frontend.Variable
	AssetID       frontend.Variable
	AssetAmount   frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	ZoneDataHash  frontend.Variable
	ZoneProgramID frontend.Variable
}

// FieldsFromUtxo maps a native protocol.Utxo to its in-circuit field layout.
// Shared by the prover witness builder and tests so the two cannot drift.
func FieldsFromUtxo(u protocol.Utxo) UtxoCircuitFields {
	return UtxoCircuitFields{
		Domain:        u.Domain,
		Owner:         u.Owner,
		AssetID:       u.AssetID,
		AssetAmount:   u.AssetAmount,
		Blinding:      u.Blinding,
		DataHash:      u.DataHash,
		ZoneDataHash:  u.ZoneDataHash,
		ZoneProgramID: u.ZoneProgramID,
	}
}

func UtxoHashCircuit(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	// owner_utxo_hash = Poseidon(owner, blinding) hides the owner inside the
	// commitment (needed for owner-hiding proofless shields). Must match
	// protocol.UtxoHash / OwnerUtxoHash.
	ownerUtxoHash := poseidon.HashCircuit(api, []frontend.Variable{u.Owner, u.Blinding})
	return poseidon.HashCircuit(api, []frontend.Variable{
		u.Domain,
		u.AssetID,
		u.AssetAmount,
		u.DataHash,
		u.ZoneDataHash,
		u.ZoneProgramID,
		ownerUtxoHash,
	})
}

// NullifierHashCircuit mirrors protocol.NullifierHash: the Poseidon image
// itself, a canonical field element. The nullifier tree's indexed-value
// domain spans the whole field (init sentinel p-1), so no truncation is
// needed.
func NullifierHashCircuit(
	api frontend.API,
	utxoHash frontend.Variable,
	blinding frontend.Variable,
	nullifierSecret frontend.Variable,
) frontend.Variable {
	return poseidon.HashCircuit(api, []frontend.Variable{
		utxoHash,
		blinding,
		nullifierSecret,
	})
}
