// Proving benchmarks for the spp_transaction circuit variants. Every timed
// proof runs against the committed, lockfile-pinned proving key, so a result is
// attributable to a key version and comparable to what the server does per
// request: build the witness, then prove.
package transaction

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/common"
	"zolana/prover/prover/fingerprint"
	"zolana/prover/prover/provingkeys"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

const (
	// benchKeysDirEnv overrides where the pinned proving keys live.
	benchKeysDirEnv = "ZOLANA_SPP_KEYS_DIR"
	// benchAllShapesEnv extends the run from the representative shape subset to
	// every shape with a pinned key.
	benchAllShapesEnv = "ZOLANA_BENCH_ALL_SHAPES"
	// benchDefaultKeysDir is prover/server/proving-keys relative to this package.
	benchDefaultKeysDir = "../../../../proving-keys"
)

// benchRail is one circuit variant plus the naming it uses on disk.
type benchRail struct {
	name        string
	circuitType common.CircuitType
	keyPrefix   string
	variant     transfereddsaonly.Variant
	p256        bool
}

func benchRails() []benchRail {
	return []benchRail{
		{
			name:        "confidential",
			circuitType: common.TransferConfidentialCircuitType,
			keyPrefix:   "transfer_confidential",
			variant:     transfereddsaonly.ConfidentialVariant,
		},
		{
			name:        "zone",
			circuitType: common.TransferZoneCircuitType,
			keyPrefix:   "transfer_zone",
			variant:     transfereddsaonly.ZoneVariant,
		},
		{
			name:        "zone_authority",
			circuitType: common.TransferZoneAuthorityCircuitType,
			keyPrefix:   "transfer_zone_authority",
			variant:     transfereddsaonly.ZoneAuthorityVariant,
		},
		{
			name:        "p256",
			circuitType: common.TransferP256ZoneCircuitType,
			keyPrefix:   "transfer_p256_zone",
			p256:        true,
		},
	}
}

// benchShapes keeps a default run short: the P256 rail alone costs roughly five
// times an eddsa proof, and a full sweep loads every pinned key from disk. 2x2
// is included because the authority rail only has square-shape keys.
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
	manifest, err := provingkeys.Load()
	if err != nil {
		b.Fatalf("load proving-keys lockfile: %v", err)
	}
	keysDir := benchKeysDir()
	b.Logf("proving keys: %s (lockfile prefix %s)", keysDir, manifest.Prefix)

	for _, rail := range benchRails() {
		for _, shape := range benchShapes() {
			b.Run(fmt.Sprintf("%s/%dx%d", rail.name, shape.NInputs, shape.NOutputs), func(b *testing.B) {
				benchmarkProveShape(b, keysDir, manifest, rail, shape)
			})
			// The combination's key manager and proving key die with the frame
			// above; collect them here so a sweep holds one key at a time
			// instead of all 34.
			runtime.GC()
		}
	}
}

func benchmarkProveShape(
	b *testing.B,
	keysDir string,
	manifest *provingkeys.Manifest,
	rail benchRail,
	shape protocol.Shape,
) {
	keyFile := fmt.Sprintf("%s_%d_%d.key", rail.keyPrefix, shape.NInputs, shape.NOutputs)
	if _, pinned := manifest.Keys[keyFile]; !pinned {
		b.Skipf("%s is not pinned in proving-keys.lock: this variant has no key for shape %s", keyFile, shape)
	}

	// One manager per combination: it caches every system it loads and offers no
	// eviction, so a shared manager would keep all 34 pinned keys resident.
	proofSystem, err := common.NewLazyKeyManager(keysDir, nil).GetTransferSystem(
		rail.circuitType,
		uint32(shape.NInputs),
		uint32(shape.NOutputs),
	)
	if err != nil {
		b.Fatalf("load %s: %v", keyFile, err)
	}
	assertPinnedFingerprint(b, keyFile, proofSystem.ConstraintSystem)

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

// assertPinnedFingerprint checks the constraint system carried by the downloaded
// key against fingerprint.KeyPinned. A mismatch means the key set changed under
// the same lockfile prefix, which invalidates every recorded measurement for that
// key. The source-side comparison, and the drift between the two sides, is the
// fingerprint package's own test.
func assertPinnedFingerprint(b *testing.B, keyFile string, cs constraint.ConstraintSystem) {
	pinned, ok := fingerprint.KeyPinned[strings.TrimSuffix(keyFile, ".key")]
	if !ok {
		return
	}
	constraints := cs.GetNbConstraints()
	public := cs.GetNbPublicVariables()
	if constraints != pinned.Constraints || public != pinned.Public {
		b.Fatalf(
			"%s carries a different constraint system than fingerprint.KeyPinned records "+
				"(constraints %d, want %d; public %d, want %d). Either the key set was "+
				"rotated without updating the fingerprints, or this key does not belong to "+
				"the version in prover/provingkeys/proving-keys.lock.",
			keyFile, constraints, pinned.Constraints, public, pinned.Public,
		)
	}
}

func benchKeysDir() string {
	if dir := os.Getenv(benchKeysDirEnv); dir != "" {
		return dir
	}
	return filepath.Clean(benchDefaultKeysDir)
}
