package shared_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

// Same one-input, two-output shape on both confidential rails. These measure
// CPU proof generation, excluding compilation, setup, witness encoding and
// verification. Every timed proof is verified outside the timer.
func BenchmarkPaymentProofs(b *testing.B) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	b.Run("default_ring", func(b *testing.B) {
		a := buildDefaultRingConfidentialEddsaAssignment(b, shape)
		benchmarkPaymentProof(b, MustNewDefaultRingConfidentialEddsaCircuit(Shape(shape)), asDefaultRingConfidentialEddsa(a))
	})
	b.Run("custom_ring_settlement", func(b *testing.B) {
		a := buildCircuitAssignment(b, shape)
		benchmarkPaymentProof(b, MustNewCustomRingConfidentialEddsaCircuit(Shape(shape)), asCustomRingConfidentialEddsa(a))
	})
	b.Run("custom_ring_auditor", func(b *testing.B) {
		circuit, err := base.NewPackedAuditCircuit(shape.NOutputs)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkPaymentProof(b, circuit, ringaudit.NewPackedAudit(b, shape.NOutputs).Circuit(b))
	})
}

// Three published outputs use the 2x4 settlement key. Constraint count and
// proving cost belong to that compiled shape, including its fourth slot.
func BenchmarkTwoByThreeSettlement(b *testing.B) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 4}
	b.Run("default_ring", func(b *testing.B) {
		a := buildDefaultRingConfidentialEddsaAssignment(b, shape)
		benchmarkPaymentProof(b, MustNewDefaultRingConfidentialEddsaCircuit(Shape(shape)), asDefaultRingConfidentialEddsa(a))
	})
	b.Run("custom_ring", func(b *testing.B) {
		a := buildCircuitAssignment(b, shape)
		benchmarkPaymentProof(b, MustNewCustomRingConfidentialEddsaCircuit(Shape(shape)), asCustomRingConfidentialEddsa(a))
	})
}

func benchmarkPaymentProof(b *testing.B, circuit, assignment frontend.Circuit) {
	b.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		b.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		proof, err := groth16.Prove(cs, pk, witness)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if err := groth16.Verify(proof, vk, public); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
	b.ReportMetric(float64(cs.GetNbConstraints()), "constraints")
}
