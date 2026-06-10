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
	// owner_utxo_hash = Poseidon(owner, blinding) nests the owner so the
	// commitment preimage never exposes it (enables owner-hiding proofless
	// shields). Must match protocol.UtxoHash / OwnerUtxoHash.
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

// canonicalTruncate248 returns the low 248 bits of x using a CANONICAL bit
// decomposition. This is the one soundness-critical step of nullifier
// derivation, kept in a single named place the alias test
// (TestCircuitRejectsUntruncatedAndAliasNullifier) pins: gnark's full-width
// ToBinary (NbDigits == FieldBitLen) constrains the bits to be < p, the only
// thing stopping the x vs x+p alias — whose low 248 bits differ — from yielding
// a second valid nullifier for the same UTXO, i.e. a double spend. Do NOT pass
// a reduced WithNbDigits: that drops the < p check and reintroduces the alias.
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
