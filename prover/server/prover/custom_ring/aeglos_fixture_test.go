package custom_ring

import (
	"os"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover-test/aeglosfixture"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// One witness per key, decoded from its request as the server decodes it.
func TestExportAeglosRingFixtures(t *testing.T) {
	if os.Getenv("AEGLOS_FIXTURES") == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	for circuit, params := range hostRequests(t) {
		aeglosfixture.Write(t, common.RingKeyFile(circuit), 0, decodeParams(t, circuit, params))
	}
}
