package merge_test

import (
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/aeglosfixture"
	"os"
	"testing"
)

func TestExportAeglosMergeFixtures(t *testing.T) {
	if os.Getenv("AEGLOS_FIXTURES") == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	for _, inputs := range mergeshared.SupportedInputCounts {
		for _, rail := range exportedMergeRails {
			for variant := range 2 {
				aeglosfixture.Write(t, rail.keyFile(inputs), variant, newHonestMerge(t, rail, inputs, variant).witness)
			}
		}
	}
}
