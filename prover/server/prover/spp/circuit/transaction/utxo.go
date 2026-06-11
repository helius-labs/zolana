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

// canonicalTruncate248 returns the low 248 bits of x. The full-width ToBinary
// is load-bearing: it constrains the bits < p, so x and x+p (equal mod p, but
// different low 248 bits) can't both pass. That alias would be a second
// nullifier for one UTXO, i.e. a double spend. Don't pass a smaller NbDigits;
// it drops the < p check. Pinned by TestCanonicalTruncate248RejectsAliasBits.
func canonicalTruncate248(api frontend.API, x frontend.Variable) frontend.Variable {
	bits := api.ToBinary(x)
	return api.FromBinary(bits[:nullifierDomainBits]...)
}

// NullifierHashCircuit mirrors protocol.NullifierHash: the Poseidon image
// truncated to the nullifier tree's 248-bit indexed value domain
// (light-batched-merkle-tree; values >= 2^248 could never be batch-proven).
func NullifierHashCircuit(
	api frontend.API,
	utxoHash frontend.Variable,
	blinding frontend.Variable,
	nullifierSecret frontend.Variable,
) frontend.Variable {
	full := poseidon.HashCircuit(api, []frontend.Variable{
		utxoHash,
		blinding,
		nullifierSecret,
	})
	return canonicalTruncate248(api, full)
}
