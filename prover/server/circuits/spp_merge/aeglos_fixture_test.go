package merge_test

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"os"
	"testing"
	"zolana/prover/prover-test/aeglosfixture"
)

func TestExportAeglosMergeFixtures(t *testing.T) {
	if os.Getenv("AEGLOS_FIXTURES") == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	for _, inputs := range []int{8, 36} {
		for _, ring := range []bool{false, true} {
			for variant := range 2 {
				options := mergeFixtureOptions{inputCount: inputs, eddsa: true, externalDataHash: big.NewInt(int64(900 + variant))}
				family := "merge"
				if ring {
					family = "merge_ring"
					options.rail = ringFixtureRail
					options.ringProgramID = big.NewInt(71)
					options.inputRingData = []*big.Int{big.NewInt(31), big.NewInt(32)}
					options.outputRingData = big.NewInt(33)
				}
				fixture := buildMergeFixture(t, options)
				var circuit frontend.Circuit = fixture.defaultCircuit()
				if ring {
					circuit = fixture.ringCircuit()
				}
				aeglosfixture.Write(t, fmt.Sprintf("%s_%d_1.key", family, inputs), variant, circuit)
			}
		}
	}
}
