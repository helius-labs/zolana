// Proving benchmarks for the spp_transaction circuit variants. Every timed proof
// is one server-side proof -- build the witness, then prove -- measuring what the
// server does per request.
//
// The keys are generated locally by a real groth16.Setup, not loaded from the
// committed set: this branch's circuits carry EdDSA-Poseidon spend authority, so
// no pinned key can prove their witnesses. A locally set up key has the same
// structure as a committed one, so these timings stay comparable to earlier
// committed-key rows, but the proofs verify against no published verifying key.
package transaction

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/common"
	"zolana/prover/prover/fingerprint"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// benchAllShapesEnv extends the run from the representative shape subset to
// every supported shape.
const benchAllShapesEnv = "ZOLANA_BENCH_ALL_SHAPES"

// benchRail is one circuit variant.
type benchRail struct {
	name    string
	variant transfereddsaonly.Variant
	p256    bool
}

func benchRails() []benchRail {
	return []benchRail{
		{name: "confidential", variant: transfereddsaonly.ConfidentialVariant},
		{name: "zone", variant: transfereddsaonly.ZoneVariant},
		{name: "zone_authority", variant: transfereddsaonly.ZoneAuthorityVariant},
		{name: "p256", p256: true},
	}
}

// benchShapes keeps a default run short: the P256 rail alone costs roughly five
// times an eddsa proof, and every combination pays a compile and a setup before
// its timer starts.
func benchShapes() []protocol.Shape {
	if os.Getenv(benchAllShapesEnv) == "1" {
		return protocol.SupportedShapes
	}
	return []protocol.Shape{
		{NInputs: 1, NOutputs: 2},
		{NInputs: 2, NOutputs: 2},
		{NInputs: 2, NOutputs: 3},
		{NInputs: 5, NOutputs: 4},
	}
}

func BenchmarkSppTransfer(b *testing.B) {
	for _, rail := range benchRails() {
		for _, shape := range benchShapes() {
			b.Run(fmt.Sprintf("%s/%dx%d", rail.name, shape.NInputs, shape.NOutputs), func(b *testing.B) {
				benchmarkProveShape(b, rail, shape)
			})
			// The combination's constraint system and proving key die with the
			// frame above; collect them here so a sweep holds one at a time.
			runtime.GC()
		}
	}
}

func benchmarkProveShape(b *testing.B, rail benchRail, shape protocol.Shape) {
	// Compile and setup run before the timer starts, so a row measures proving
	// only. The setup is a real one: groth16.DummySetup fills every G1 and G2
	// point of the proving key with the same value, and multi-scalar
	// multiplication over identical points does not cost what it does over the
	// distinct points a real key carries.
	ccs, err := benchConstraintSystem(rail, shape)
	if err != nil {
		b.Fatalf("compile %s shape %s: %v", rail.name, shape, err)
	}
	provingKey, _, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatalf("setup %s shape %s: %v", rail.name, shape, err)
	}
	proofSystem := &common.TransferProofSystem{
		NInputs:          uint32(shape.NInputs),
		NOutputs:         uint32(shape.NOutputs),
		RequiresP256:     rail.p256,
		ProvingKey:       provingKey,
		ConstraintSystem: ccs,
	}
	assertPinnedFingerprint(b, benchFingerprintName(rail, shape), ccs)

	prove, err := benchProver(rail, shape, proofSystem)
	if err != nil {
		b.Fatalf("build %s parameters for shape %s: %v", rail.name, shape, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := prove(); err != nil {
			b.Fatalf("prove %s shape %s: %v", rail.name, shape, err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(proofSystem.ConstraintSystem.GetNbConstraints()), "constraints")
}

// BenchmarkSppWitness times only witness assembly: parameters onto circuit
// signals plus witness serialization. BenchmarkSppTransfer includes this cost,
// so the two together separate a witness regression from a proving one. No
// proving key is involved, so every variant covers every shape.
func BenchmarkSppWitness(b *testing.B) {
	for _, rail := range benchRails() {
		for _, shape := range benchShapes() {
			b.Run(fmt.Sprintf("%s/%dx%d", rail.name, shape.NInputs, shape.NOutputs), func(b *testing.B) {
				createWitness, err := benchWitnessBuilder(rail, shape)
				if err != nil {
					b.Fatalf("build %s parameters for shape %s: %v", rail.name, shape, err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := createWitness(); err != nil {
						b.Fatalf("create witness %s shape %s: %v", rail.name, shape, err)
					}
				}
			})
		}
	}
}

func benchWitnessBuilder(rail benchRail, shape protocol.Shape) (func() error, error) {
	assign, err := benchAssigner(rail, shape)
	if err != nil {
		return nil, err
	}
	return func() error {
		assignment, err := assign()
		if err != nil {
			return err
		}
		_, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		return err
	}, nil
}

// benchAssigner builds the parameters once and returns the per-iteration
// assignment call for the rail.
func benchAssigner(rail benchRail, shape protocol.Shape) (func() (frontend.Circuit, error), error) {
	if rail.p256 {
		params, err := BuildP256TransferParameters(shape)
		if err != nil {
			return nil, err
		}
		return params.CreateWitness, nil
	}
	params, err := BuildTransferParameters(rail.variant, shape)
	if err != nil {
		return nil, err
	}
	return params.CreateWitness, nil
}

// benchProver builds the witness parameters once and returns the timed call.
// The returned closure is exactly one server-side proof: witness assignment,
// witness serialization, and groth16.Prove.
func benchProver(
	rail benchRail,
	shape protocol.Shape,
	proofSystem *common.TransferProofSystem,
) (func() error, error) {
	if rail.p256 {
		params, err := BuildP256TransferParameters(shape)
		if err != nil {
			return nil, err
		}
		return func() error {
			_, err := transfereddsaonly.ProveP256Transfer(proofSystem, params)
			return err
		}, nil
	}
	params, err := BuildTransferParameters(rail.variant, shape)
	if err != nil {
		return nil, err
	}
	return func() error {
		_, err := transfereddsaonly.ProveTransfer(proofSystem, params)
		return err
	}, nil
}

// benchConstraintSystem compiles the production circuit for a rail and shape.
func benchConstraintSystem(rail benchRail, shape protocol.Shape) (constraint.ConstraintSystem, error) {
	if rail.p256 {
		return transfereddsaonly.R1CSP256Transfer(uint32(shape.NInputs), uint32(shape.NOutputs))
	}
	return transfereddsaonly.R1CSTransfer(uint32(shape.NInputs), uint32(shape.NOutputs), rail.variant)
}

// benchFingerprintName is the proving-key name a rail and shape would carry, so
// a benched combination can be matched against the pinned fingerprints.
func benchFingerprintName(rail benchRail, shape protocol.Shape) string {
	prefix := map[string]string{
		"confidential":   "transfer_confidential",
		"zone":           "transfer_zone",
		"zone_authority": "transfer_zone_authority",
		"p256":           "transfer_p256_zone",
	}[rail.name]
	return fmt.Sprintf("%s_%d_%d", prefix, shape.NInputs, shape.NOutputs)
}

// assertPinnedFingerprint compares a compiled constraint system against the
// fingerprints recorded for the current sources, so a benchmark row can never be
// attributed to a circuit other than the one that was pinned. Combinations with
// no pinned entry are simply not covered.
func assertPinnedFingerprint(b *testing.B, name string, cs constraint.ConstraintSystem) {
	pinned, ok := fingerprint.Pinned[name]
	if !ok {
		return
	}
	constraints := cs.GetNbConstraints()
	public := cs.GetNbPublicVariables()
	if constraints != pinned.Constraints || public != pinned.Public {
		b.Fatalf(
			"%s compiled to a different constraint system than fingerprint.Pinned records "+
				"(constraints %d, want %d; public %d, want %d). The circuit changed without "+
				"the fingerprints being updated.",
			name, constraints, pinned.Constraints, public, pinned.Public,
		)
	}
}
