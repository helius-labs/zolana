package base_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringkey"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Every audit key compiles as the ring prover compiles it, at its pinned count with one BSB22 commitment.
func TestAuditKeysCompileAtPinnedCounts(t *testing.T) {
	keys := map[string]func() (frontend.Circuit, error){}
	for _, capacity := range base.PackedAuditCapacities {
		keys[ringkey.Name(t, common.RingPackedAudit, 0, capacity)] = func() (frontend.Circuit, error) {
			return base.NewPackedAuditCircuit(capacity)
		}
	}
	for _, capacity := range base.DeliveredAuditCapacities {
		keys[ringkey.Name(t, common.RingDeliveredAudit, 0, capacity)] = func() (frontend.Circuit, error) {
			return base.NewDeliveredAuditCircuit(capacity)
		}
	}
	for _, shape := range slices.Concat(base.AnonymousAuditShapes[:], base.AnonymousEntryShapes[:]) {
		keys[anonymousKeyName(t, shape)] = func() (frontend.Circuit, error) {
			return base.NewAnonymousAuditCircuit(shape)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(keys)) {
		t.Run(name, func(t *testing.T) {
			circuit, err := keys[name]()
			if err != nil {
				t.Fatal(err)
			}
			ringkey.RequirePinned(t, name, ringkey.Compile(t, circuit))
		})
	}
}

func anonymousKeyName(t testing.TB, shape base.AnonymousAuditShape) string {
	t.Helper()
	family := common.RingAnonymousAudit
	if shape.FullOpenings {
		family = common.RingAnonymousEntryAudit
	}
	return ringkey.Name(t, family, shape.InputClass, shape.Outputs)
}
