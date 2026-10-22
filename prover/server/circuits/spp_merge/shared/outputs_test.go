package shared

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"math/big"
	"testing"
)

type mergeOutputAssetCircuit struct{ Asset, Hash frontend.Variable }

func (c *mergeOutputAssetCircuit) Define(api frontend.API) error {
	constrainOutput(api, Output{RingDataHash: 0}, c.Hash, 9, 7, c.Asset, 1, 0, 1)
	return nil
}

// The merge output is always a real note, so it inherits the common nonzero
// asset check. SOL's zero mint address is a valid nonzero hashed asset.
func TestMergeOutputRejectsZeroAssetAndAcceptsSOL(t *testing.T) {
	for _, tc := range []struct {
		name  string
		asset *big.Int
		valid bool
	}{
		{"zero_asset_field", big.NewInt(0), false},
		{"zero_SOL_mint_address", protocol.SolAsset(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := protocol.UtxoHash(protocol.Utxo{Domain: big.NewInt(UtxoDomain), Owner: big.NewInt(7), Asset: tc.asset, Amount: big.NewInt(1), Blinding: big.NewInt(9), DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0)}, big.NewInt(1))
			if err != nil {
				t.Fatal(err)
			}
			err = test.IsSolved(&mergeOutputAssetCircuit{}, &mergeOutputAssetCircuit{Asset: tc.asset, Hash: hash}, ecc.BN254.ScalarField())
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, got %v", tc.valid, err)
			}
		})
	}
}
