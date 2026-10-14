package custom_ring

import (
	"math/big"
	"os"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover-test/aeglosfixture"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestExportAeglosRingFixtures(t *testing.T) {
	if os.Getenv("AEGLOS_FIXTURES") == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	for variant := range 2 {
		base := baseParams(t)
		base.PrivateTxHash = fi(int64(1000 + variant))
		keys := ringaudit.DefaultKeys(t)
		base.PublicInputHash = fb(spptest.MustHashChain(t, keys.ChainElementsFor(t, keys.AuditBlockWires(base.PrivateTxHash.Int), int(base.NOut))))
		aeglosfixture.Write(t, "custom_ring_base.key", variant, decodeParams(t, common.CustomRingBaseCircuitType, base))
		policy := rulesFreeParamsAtRoot(t, big.NewInt(int64(13+variant)))
		aeglosfixture.Write(t, "custom_ring_policy.key", variant, decodeParams(t, common.CustomRingPolicyCircuitType, policy))
	}
}
