package transaction

import (
	"encoding/json"
	"os"

	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
)

// ProoflessCommitment is the output of deriving a proofless-shield UTXO
// commitment. The on-chain ProoflessShieldData carries OwnerUtxoHash, which
// hides the recipient; the depositor records UtxoHash off-chain as the
// state-tree leaf so the public deposit can later be spent by a proof.
type ProoflessCommitment struct {
	Owner         string `json:"owner"`
	OwnerUtxoHash string `json:"owner_utxo_hash"`
	UtxoHash      string `json:"utxo_hash"`
}

// ComputeProoflessCommitment derives the owner-hiding commitment for a single
// proofless-shield output UTXO. It reuses the exact owner/UTXO derivation of
// the proving path (parseProofUtxo + protocol.UtxoHash), so a proofless deposit
// is byte-identical to what a proof would have produced and stays spendable.
// The request must be a bare default-zone UTXO: parseProofUtxo rejects non-zero
// data/zone fields, matching the on-chain proofless_shield check.
func ComputeProoflessCommitment(request ProofUtxoRequest) (ProoflessCommitment, error) {
	parsed, err := parseProofUtxo(request, nil)
	if err != nil {
		return ProoflessCommitment{}, err
	}
	ownerUtxoHash, err := protocol.OwnerUtxoHash(parsed.utxo.Owner, parsed.utxo.Blinding)
	if err != nil {
		return ProoflessCommitment{}, err
	}
	utxoHash, err := protocol.UtxoHash(parsed.utxo)
	if err != nil {
		return ProoflessCommitment{}, err
	}
	return ProoflessCommitment{
		Owner:         parse.FieldHex(parsed.utxo.Owner),
		OwnerUtxoHash: parse.FieldHex(ownerUtxoHash),
		UtxoHash:      parse.FieldHex(utxoHash),
	}, nil
}

// WriteProoflessCommitment reads a single output-UTXO request from requestPath
// and writes its ProoflessCommitment to outputPath. No proving system is
// needed: the commitment is pure Poseidon hashing.
func WriteProoflessCommitment(requestPath string, outputPath string) error {
	bytes, err := os.ReadFile(requestPath)
	if err != nil {
		return err
	}
	var request ProofUtxoRequest
	if err := json.Unmarshal(bytes, &request); err != nil {
		return err
	}
	commitment, err := ComputeProoflessCommitment(request)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(commitment, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(outputPath, out, 0644)
}
