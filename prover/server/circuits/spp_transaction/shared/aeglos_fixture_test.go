package shared_test

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"testing/cryptotest"

	"github.com/consensys/gnark/frontend"
	customring "zolana/prover/circuits/spp_transaction/custom"
	defaultring "zolana/prover/circuits/spp_transaction/default"
	"zolana/prover/prover-test/aeglosfixture"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/provingkeys"
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
		for _, family := range []string{"transfer_ring", "transfer_confidential", "transfer_p256_ring", "transfer_ring_authority"} {
			name := fmt.Sprintf("%s_%d_%d.key", family, shape.NInputs, shape.NOutputs)
			if _, ok := manifest.Keys[name]; !ok {
				continue
			}
			for variant := range 2 {
				var assignment *testAssignment
				switch family {
				case "transfer_confidential":
					assignment = buildDefaultRingEddsaOnlyAssignment(t, shape)
				case "transfer_ring_authority":
					assignment = buildRingAuthorityAssignment(t, shape)
				default:
					assignment = buildCircuitAssignment(t, shape)
				}
				assignment.BlindingSeed = big.NewInt(int64(800 + variant))
				rebuildAfterOwnerChange(t, assignment)
				var circuit frontend.Circuit
				switch family {
				case "transfer_ring":
					circuit = asCustomRingEddsaOnly(assignment)
					circuit.(*customring.CustomRingEddsaOnlyCircuit).Shape = assignment.Shape
				case "transfer_confidential":
					refreshDefaultRingPublicInputHash(t, assignment)
					circuit = asDefaultRingEddsaOnly(assignment)
					circuit.(*defaultring.DefaultRingEddsaOnlyCircuit).Shape = assignment.Shape
				case "transfer_ring_authority":
					refreshRingAuthorityPublicInputHash(t, assignment)
					circuit = asCustomRingAuthority(assignment)
					circuit.(*customring.CustomRingAuthorityCircuit).Shape = assignment.Shape
				case "transfer_p256_ring":
					owner := spptest.FixedP256Key(t, 11)
					rewriteInputAsP256(t, assignment, 0, owner)
					authorization := authorizeP256(t, assignment, owner, owner)
					circuit = asCustomRingP256(assignment, authorization)
					circuit.(*customring.CustomRingP256Circuit).Shape = assignment.Shape
				}
				aeglosfixture.Write(t, name, variant, circuit)
			}
		}
	}
}
