package transaction

import (
	"math/big"
	"testing"

	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
)

// TestComputeProoflessCommitmentMatchesProvenOutput pins the spendability
// invariant: a proofless deposit's state-tree leaf (utxo_hash) must be
// byte-identical to the leaf a proven output with the same fields would
// produce, and owner_utxo_hash must be Poseidon(owner, blinding) for the
// derived owner. Otherwise a proofless deposit could never be spent by a proof.
func TestComputeProoflessCommitmentMatchesProvenOutput(t *testing.T) {
	var pubkey [32]byte
	for i := range pubkey {
		pubkey[i] = byte(i + 7)
	}
	blinding := big.NewInt(99)
	req := ProofUtxoRequest{
		Domain:               proofFieldInput(big.NewInt(protocol.UtxoDomain)),
		OwnerSolanaPubkey:    parse.BytesHex(pubkey[:]),
		OwnerNullifierSecret: proofFieldInput(big.NewInt(424242)),
		AssetID:              proofFieldInput(protocol.SolAsset()),
		AssetAmount:          proofFieldInput(big.NewInt(5_000_000)),
		Blinding:             proofFieldInput(blinding),
		DataHash:             proofFieldInput(big.NewInt(0)),
		ZoneDataHash:         proofFieldInput(big.NewInt(0)),
		ZoneProgramID:        proofFieldInput(big.NewInt(0)),
	}

	commitment, err := ComputeProoflessCommitment(req)
	if err != nil {
		t.Fatal(err)
	}

	shape, err := protocol.CanonicalShape(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := buildOutputWitnesses(shape, []ProofUtxoRequest{req})
	if err != nil {
		t.Fatal(err)
	}
	if got := parse.FieldHex(outputs.hashes[0]); got != commitment.UtxoHash {
		t.Fatalf("utxo_hash mismatch: proofless %s vs proven output %s", commitment.UtxoHash, got)
	}

	// owner = OwnerHash(SolanaPkHash(pubkey), NullifierPk(secret)); the
	// commitment must expose it and nest it as owner_utxo_hash = Poseidon(owner,
	// blinding).
	keyHash, err := protocol.SolanaPkHash(pubkey)
	if err != nil {
		t.Fatal(err)
	}
	nullifierPk, err := protocol.NullifierPk(big.NewInt(424242))
	if err != nil {
		t.Fatal(err)
	}
	wantOwner, err := protocol.OwnerHash(keyHash, nullifierPk)
	if err != nil {
		t.Fatal(err)
	}
	if got := parse.FieldHex(wantOwner); got != commitment.Owner {
		t.Fatalf("owner mismatch: %s vs %s", commitment.Owner, got)
	}
	wantOwnerUtxo, err := protocol.OwnerUtxoHash(wantOwner, blinding)
	if err != nil {
		t.Fatal(err)
	}
	if got := parse.FieldHex(wantOwnerUtxo); got != commitment.OwnerUtxoHash {
		t.Fatalf("owner_utxo_hash mismatch: %s vs %s", commitment.OwnerUtxoHash, got)
	}
}
