package base_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

var pinnedAuditConstraints = map[string]int{
	"custom_ring_audit_packed_2":            53502,
	"custom_ring_audit_packed_4":            64827,
	"custom_ring_audit_delivered_8":         284405,
	"custom_ring_audit_delivered_16":        524519,
	"custom_ring_audit_anonymous_4_2":       124482,
	"custom_ring_audit_anonymous_8_2":       132059,
	"custom_ring_audit_anonymous_12_2":      139639,
	"custom_ring_audit_anonymous_16_2":      147222,
	"custom_ring_audit_anonymous_24_2":      162379,
	"custom_ring_audit_anonymous_28_2":      169962,
	"custom_ring_audit_anonymous_4_4":       186375,
	"custom_ring_audit_anonymous_8_4":       193952,
	"custom_ring_audit_anonymous_12_4":      201532,
	"custom_ring_audit_anonymous_16_4":      209115,
	"custom_ring_audit_anonymous_24_4":      224272,
	"custom_ring_audit_anonymous_4_8":       311891,
	"custom_ring_audit_anonymous_8_8":       319468,
	"custom_ring_audit_anonymous_12_8":      327048,
	"custom_ring_audit_anonymous_16_8":      334631,
	"custom_ring_audit_anonymous_entry_8_2": 138157,
	"custom_ring_audit_anonymous_entry_8_4": 200050,
	"custom_ring_audit_anonymous_entry_8_8": 325566,
}

// Every audit key compiles as the ring prover compiles it, at its pinned count with one BSB22 commitment.
func TestAuditKeysCompileAtPinnedCounts(t *testing.T) {
	keys := map[string]func() (frontend.Circuit, error){}
	for _, capacity := range base.PackedAuditCapacities {
		keys[keyName(t, common.RingPackedAudit, 0, capacity)] = func() (frontend.Circuit, error) {
			return base.NewPackedAuditCircuit(capacity)
		}
	}
	for _, capacity := range base.DeliveredAuditCapacities {
		keys[keyName(t, common.RingDeliveredAudit, 0, capacity)] = func() (frontend.Circuit, error) {
			return base.NewDeliveredAuditCircuit(capacity)
		}
	}
	for _, shape := range slices.Concat(base.AnonymousAuditShapes[:], base.AnonymousEntryShapes[:]) {
		keys[anonymousKeyName(t, shape)] = func() (frontend.Circuit, error) {
			return base.NewAnonymousAuditCircuit(shape)
		}
	}
	if names := slices.Sorted(maps.Keys(keys)); !slices.Equal(names, slices.Sorted(maps.Keys(pinnedAuditConstraints))) {
		t.Fatalf("audit keys %v differ from the pinned set", names)
	}
	for _, name := range slices.Sorted(maps.Keys(keys)) {
		t.Run(name, func(t *testing.T) {
			circuit, err := keys[name]()
			if err != nil {
				t.Fatal(err)
			}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := cs.GetNbConstraints(), pinnedAuditConstraints[name]; got != want {
				t.Errorf("%d constraints, pinned %d", got, want)
			}
			// groth16-solana verifies one BSB22 commitment over private wires, its key parser refuses a committed public wire.
			commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
			if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
				t.Errorf("commitments %v, want one over private wires", cs.GetCommitments())
			}
		})
	}
}

// keyName is the catalog's name of the key a shape compiles to, so every pin names the key it guards.
func keyName(t testing.TB, family common.RingFamily, inputs, outputs int) string {
	t.Helper()
	for _, key := range common.RingKeys {
		if key.Family == family && key.Inputs == inputs && key.Outputs == outputs {
			return strings.TrimSuffix(common.RingKeyFile(key.Circuit), ".key")
		}
	}
	t.Fatalf("no catalog key of family %d for %d inputs and %d outputs", family, inputs, outputs)
	return ""
}

func anonymousKeyName(t testing.TB, shape base.AnonymousAuditShape) string {
	t.Helper()
	family := common.RingAnonymousAudit
	if shape.FullOpenings {
		family = common.RingAnonymousEntryAudit
	}
	return keyName(t, family, shape.InputClass, shape.Outputs)
}
