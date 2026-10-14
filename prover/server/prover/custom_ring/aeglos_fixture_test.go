package custom_ring

import (
	"math/big"
	"os"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover-test/aeglosfixture"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func TestExportAeglosRingFixtures(t *testing.T) {
	if os.Getenv("AEGLOS_FIXTURES") == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	for variant := range 2 {
		base := baseParams(t)
		base.PrivateTxHash = big.NewInt(int64(1000 + variant))
		keys := ringaudit.DefaultKeys(t)
		elements := keys.ChainElementsFor(t, keys.AuditBlockWires(base.PrivateTxHash), int(base.NOut))
		base.PublicInputHash = spptest.MustHashChain(t, elements)
		baseWitness, err := base.CreateWitness()
		if err != nil {
			t.Fatal(err)
		}
		aeglosfixture.Write(t, "custom_ring_base.key", variant, baseWitness)
		policy := rulesFreeParamsAtRoot(t, big.NewInt(int64(13+variant)))
		policyWitness, err := policy.CreateWitness()
		if err != nil {
			t.Fatal(err)
		}
		aeglosfixture.Write(t, "custom_ring_policy.key", variant, policyWitness)
	}
}
