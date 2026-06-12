package poseidon

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
)

// TestConstantsConsistency cross-checks the bench-derived ARK_t / MDSt tables
// (used by HashWithT and HashCircuitWithT) against the legacy CONSTANTS_t /
// MDS_t tables (used by the Poseidon1/2/3 gadgets) for widths t in {2, 3, 4}.
// Both encode the same Circom-compatible Poseidon parameters; this test fails
// loudly if either table drifts.
func TestConstantsConsistency(t *testing.T) {
	cases := []struct {
		t         int
		legacyArk [][]frontend.Variable
		legacyMds [][]frontend.Variable
		newArk    [][]*big.Int
		newMds    [][]*big.Int
	}{
		{2, CONSTANTS_2, MDS_2, CFG[2].ARK, MDS2},
		{3, CONSTANTS_3, MDS_3, CFG[3].ARK, MDS3},
		{4, CONSTANTS_4, MDS_4, CFG[4].ARK, MDS4},
	}

	for _, c := range cases {
		if len(c.newArk) != len(c.legacyArk) {
			t.Fatalf("t=%d: ARK round count mismatch: new=%d legacy=%d", c.t, len(c.newArk), len(c.legacyArk))
		}
		for r := range c.newArk {
			if len(c.newArk[r]) != len(c.legacyArk[r]) {
				t.Fatalf("t=%d: ARK row %d width mismatch", c.t, r)
			}
			for i := range c.newArk[r] {
				legacy := asBigInt(c.legacyArk[r][i])
				if c.newArk[r][i].Cmp(legacy) != 0 {
					t.Fatalf("t=%d: ARK[%d][%d] mismatch:\n  new    = 0x%s\n  legacy = 0x%s", c.t, r, i, c.newArk[r][i].Text(16), legacy.Text(16))
				}
			}
		}

		if len(c.newMds) != len(c.legacyMds) {
			t.Fatalf("t=%d: MDS row count mismatch: new=%d legacy=%d", c.t, len(c.newMds), len(c.legacyMds))
		}
		for i := range c.newMds {
			if len(c.newMds[i]) != len(c.legacyMds[i]) {
				t.Fatalf("t=%d: MDS row %d width mismatch", c.t, i)
			}
			for j := range c.newMds[i] {
				legacy := asBigInt(c.legacyMds[i][j])
				if c.newMds[i][j].Cmp(legacy) != 0 {
					t.Fatalf("t=%d: MDS[%d][%d] mismatch:\n  new    = 0x%s\n  legacy = 0x%s", c.t, i, j, c.newMds[i][j].Text(16), legacy.Text(16))
				}
			}
		}
	}
}

// asBigInt extracts a *big.Int from a legacy table cell. Legacy cells are
// frontend.Variable values produced by hex(...) which returns big.Int by value.
func asBigInt(v frontend.Variable) *big.Int {
	switch x := v.(type) {
	case big.Int:
		r := new(big.Int).Set(&x)
		return r
	case *big.Int:
		return x
	}
	panic("consistency_test: unexpected legacy cell type")
}
