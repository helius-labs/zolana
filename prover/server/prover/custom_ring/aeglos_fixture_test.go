package custom_ring

import (
	"math/big"
	"os"
	"testing"
	"zolana/prover/prover-test/aeglosfixture"
	"zolana/prover/prover-test/spp/spptest"
)

func TestExportAeglosRingFixtures(t *testing.T) {
	if os.Getenv("AEGLOS_FIXTURES") == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	for variant := range 2 {
		base := baseParams(t)
		base.PrivateTxHash = big.NewInt(int64(1000 + variant))
		elements := []*big.Int{base.PrivateTxHash}
		for _, text := range auditChainElements {
			value, ok := new(big.Int).SetString(text[2:], 16)
			if !ok {
				t.Fatal("invalid audit element")
			}
			elements = append(elements, value)
		}
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
