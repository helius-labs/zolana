package shared_test

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"testing/cryptotest"

	"github.com/consensys/gnark/frontend"
	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	defaultring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/default"
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
		for _, family := range []string{"transfer_ring", "transfer_confidential", "transfer_ring_authority"} {
			name := fmt.Sprintf("%s_%d_%d.key", family, shape.NInputs, shape.NOutputs)
			if _, ok := manifest.Keys[name]; !ok {
				continue
			}
			for variant := range 2 {
				var assignment *testAssignment
				switch family {
				case "transfer_confidential":
					assignment = buildDefaultRingConfidentialEd25519Assignment(t, shape)
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
					circuit = asCustomRingConfidentialEd25519(assignment)
					circuit.(*customring.CustomRingConfidentialEd25519Circuit).Shape = assignment.Shape
				case "transfer_confidential":
					refreshDefaultRingPublicInputHash(t, assignment)
					circuit = asDefaultRingConfidentialEd25519(assignment)
					circuit.(*defaultring.DefaultRingConfidentialEd25519Circuit).Shape = assignment.Shape
				case "transfer_ring_authority":
					refreshRingAuthorityPublicInputHash(t, assignment)
					circuit = asCustomRingAuthority(assignment)
					circuit.(*customring.CustomRingAuthorityCircuit).Shape = assignment.Shape
				}
				aeglosfixture.Write(t, name, variant, circuit)
			}
		}
	}
}
