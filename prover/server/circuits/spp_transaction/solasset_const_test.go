package transaction_test

import (
	"testing"

	. "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/protocol"
)

// TestSolAssetConstantMatchesHost pins the circuit's hardcoded solAssetValue
// (via SolAsset) to the host hash_bytes([0;32]). A drift here means every SOL
// UTXO's asset field would disagree with the circuit and no proof would verify.
func TestSolAssetConstantMatchesHost(t *testing.T) {
	got := SolAsset()
	want := protocol.SolAsset()
	if got.Cmp(want) != 0 {
		t.Fatalf("solAssetValue mismatch: circuit %s host %s", got, want)
	}
}
