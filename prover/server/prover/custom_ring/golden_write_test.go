package custom_ring

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// WRITE_RING_GOLDENS=1 rewrites testdata/*.json from the host builders, one
// accepted statement per circuit and the policy sample the decoder tests tamper.
func TestWriteGoldenRequests(t *testing.T) {
	if os.Getenv("WRITE_RING_GOLDENS") == "" {
		t.Skip("WRITE_RING_GOLDENS=1 rewrites the request fixtures")
	}
	write := func(name string, params any) {
		t.Helper()
		encoded, err := json.MarshalIndent(params, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", name+".json"), append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(string(common.CustomRingBaseCircuitType), baseParams(t))

	member, _ := rulesFreeParams(t)
	write(string(common.CustomRingPolicyCircuitType), member)

	escrowed, members := rulesFreeParams(t)
	escrowPolicyOutputs(t, escrowed, members)
	escrowed.CircuitType = string(common.CustomRingDelegatePolicyCircuitType)
	write(string(common.CustomRingDelegatePolicyCircuitType), &DelegatePolicyParams{CircuitType: escrowed.CircuitType, Policy: *escrowed})

	// The sample spends from two trees and names a curator registry, the decoder tests tamper its fields.
	sample, sampleMembers := rulesFreeParamsAtRoot(t, big.NewInt(0x1d))
	sample.TreeSlots[1] = common.TreeSlotParams{ID: big.NewInt(0x10), UtxoRoot: big.NewInt(0x2d), NullifierRoot: big.NewInt(0x2e)}
	sample.Sources[policy.NSources-1] = Source{ListId: policy.NSources, Registry: fi(0xc0ffee)}
	curator := spptest.NewMemberRegistry(t, 20)
	curator.Update(t, big.NewInt(0x0b), big.NewInt(1<<(policy.NSources-1)), big.NewInt(0))
	sample.ForeignRoot = fb(curator.Root())
	for i, input := range sample.Inputs {
		if i < int(sample.NIn) && input.Domain.Int64() == protocol.UtxoDomain {
			sample.ForeignSubjects[i] = memberOpening(curator.Opening(input.OwnerPkHash.Int))
		}
	}
	for o, output := range sample.Outputs {
		if o < int(sample.NOut) && output.Domain.Int64() == protocol.UtxoDomain {
			sample.ForeignSubjects[policy.NInputs+o] = memberOpening(curator.Opening(output.OwnerPkHash.Int))
		}
	}
	openSubjects(sample, sampleMembers)
	bindRulesFreeStatement(t, sample)
	write(string(common.CustomRingPolicyCircuitType)+"-sample", sample)

	depositVector, _ := depositFixture(t, 2)
	escrowDeposits(t, depositVector.Params)
	encryptDepositVector(t, depositVector.Params)
	write(string(common.CustomRingDepositCircuitType), depositVector.Params)

	registry := spptest.NewMemberRegistry(t, 20)
	registry.Update(t, big.NewInt(0x0a), big.NewInt(1), big.NewInt(0))
	write(string(common.CustomRingKeyRegisterCircuitType), registerKeyParams(t, registry, big.NewInt(0x0b)))

	batch := spptest.NewMemberRegistry(t, 20)
	batch.Update(t, big.NewInt(0x40), big.NewInt(1), big.NewInt(0))
	write(string(common.CustomRingUpdateMembersCircuitType), updateMembersParams(t, batch, [][3]*big.Int{
		{big.NewInt(0x10), big.NewInt(0b11), big.NewInt(0)},
		{big.NewInt(0x40), big.NewInt(0b100), big.NewInt(0x5e)},
		{big.NewInt(0x50), big.NewInt(0), big.NewInt(0x5f)},
	}))
}
