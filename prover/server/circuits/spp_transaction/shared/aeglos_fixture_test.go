package shared_test

import (
	"os"
	"testing"
	"testing/cryptotest"

	"github.com/helius-labs/zolana/prover/server/prover-test/aeglosfixture"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

func TestExportAeglosTransferFixtures(t *testing.T) {
	if os.Getenv("AEGLOS_FIXTURES") == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	cryptotest.SetGlobalRandom(t, 0)
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range protocol.SupportedShapes {
		for _, circuit := range exportedTransfers {
			name := transferKeyFile(circuit, shape)
			if _, ok := manifest.Keys[name]; !ok {
				continue
			}
			for variant := range 2 {
				aeglosfixture.Write(t, name, variant, newHonestTransfer(t, circuit, shape, variant).witness)
			}
		}
	}
}
