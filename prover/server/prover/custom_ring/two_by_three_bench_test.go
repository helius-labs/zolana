package custom_ring

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Full-capacity policy fixtures. Compilation, setup and verification are
// excluded. Every timed proof verifies against its locally assigned statement.
func BenchmarkFullPolicyTwoByThree(b *testing.B) {
	for _, tc := range []struct {
		name          string
		fixture, kind common.CircuitType
	}{
		{"general", common.CustomRingPolicyTwoByThreeCircuitType, common.CustomRingPolicyCircuitType},
		{"ordinary", common.CustomRingPolicyTwoByThreeCircuitType, common.CustomRingPolicyTwoByThreeCircuitType},
		{"anonymous", common.CustomRingAnonymousPolicyTwoByThreeCircuitType, common.CustomRingAnonymousPolicyTwoByThreeCircuitType},
		{"delegate", common.CustomRingDelegatePolicyTwoByThreeCircuitType, common.CustomRingDelegatePolicyTwoByThreeCircuitType},
	} {
		b.Run(tc.name, func(b *testing.B) {
			payload, err := os.ReadFile(filepath.Join("testdata", string(tc.fixture)+".json"))
			if err != nil {
				b.Fatal(err)
			}
			w, err := Decode(tc.kind, payload)
			if err != nil {
				b.Fatal(err)
			}
			r, err := Ring(tc.kind)
			if err != nil {
				b.Fatal(err)
			}
			ps, err := r.Setup()
			if err != nil {
				b.Fatal(err)
			}
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				b.Fatal(err)
			}
			public, err := witness.Public()
			if err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if err := groth16.Verify(proof, ps.VerifyingKey, public); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
			b.ReportMetric(float64(ps.ConstraintSystem.GetNbConstraints()), "constraints")
		})
	}
}
