//go:build aggregate_keys

package aggregate

import (
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"testing"
	"time"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

// TestAggregateCompileCost compiles the outer circuit for every rail with a
// local inner key and reports constraints, solver depth, and the FFT domain.
// The outer cost depends on the inner circuit only through its public input
// and commitment counts, so one eddsa rail and the P256 rail cover the
// catalogue.
func TestAggregateCompileCost(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles multi-million constraint circuits")
	}
	rails := []common.AggregateSlot{
		{Inner: common.TransferRingCircuitType, NInputs: 2, NOutputs: 3},
		{Inner: common.TransferP256RingCircuitType, NInputs: 2, NOutputs: 3},
	}

	for _, rail := range rails {
		inner := loadInnerSystem(t, rail)
		if inner == nil {
			continue
		}
		for batch := MinBatch; batch <= MaxBatch; batch++ {
			p := Uniform(rail.Inner, rail.NInputs, rail.NOutputs, batch)
			vks := make([]groth16.VerifyingKey, batch)
			for i := range vks {
				vks[i] = inner.VerifyingKey
			}
			compileAndReport(t, p, vks)
		}
	}
}

// TestMixedAggregateCompileCost compiles the two mixed shapes the catalogue
// starts with. The take slot reuses the ring verifying key as a stand-in. The
// outer cost depends only on the key's public input and commitment counts,
// and the take circuit matches the eddsa rails on both.
func TestMixedAggregateCompileCost(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles multi-million constraint circuits")
	}
	confidential := loadInnerSystem(t, confidentialSlot())
	ring := loadInnerSystem(t, ringSlot())
	if confidential == nil || ring == nil {
		return
	}

	pair := Params{Slots: []common.AggregateSlot{confidentialSlot(), ringSlot()}}
	compileAndReport(t, pair, []groth16.VerifyingKey{confidential.VerifyingKey, ring.VerifyingKey})

	take := Params{Slots: []common.AggregateSlot{takeSlot(), confidentialSlot()}}
	compileAndReport(t, take, []groth16.VerifyingKey{ring.VerifyingKey, confidential.VerifyingKey})
}

// compiledShape is the pinned cost of one outer shape. A shape absent from
// wantShapes is reported and not pinned.
type compiledShape struct {
	constraints int
	levels      int
}

// wantShapes pins every catalogue shape RECURSION.md quotes. A change here
// changes the key files, so it must land with regenerated keys and constants.
var wantShapes = map[string]compiledShape{
	"aggregate_transfer_ring_2_3_b2":                               {constraints: 1059358, levels: 405},
	"aggregate_transfer_ring_2_3_b3":                               {constraints: 1556316, levels: 405},
	"aggregate_transfer_ring_2_3_b4":                               {constraints: 2053274, levels: 588},
	"aggregate_transfer_ring_2_3_b5":                               {constraints: 2550232, levels: 783},
	"aggregate_transfer_p256_ring_2_3_b2":                          {constraints: 2021698, levels: 2677},
	"aggregate_transfer_p256_ring_2_3_b3":                          {constraints: 2934159, levels: 2677},
	"aggregate_transfer_p256_ring_2_3_b4":                          {constraints: 3846620, levels: 2677},
	"aggregate_transfer_p256_ring_2_3_b5":                          {constraints: 4759082, levels: 2677},
	"aggregate_mix_transfer_confidential_2_2-transfer_ring_2_3_b2": {constraints: 1059358, levels: 405},
	"aggregate_mix_swap_take-transfer_confidential_2_2_b2":         {constraints: 1059358, levels: 405},
}

func compileAndReport(t *testing.T, p Params, vks []groth16.VerifyingKey) {
	t.Helper()
	start := time.Now()
	ccs, err := R1CSAggregate(p, vks)
	if err != nil {
		t.Fatalf("%s: %v", p.KeyName(), err)
	}
	r1cs, ok := ccs.(*cs_bn254.R1CS)
	if !ok {
		t.Fatalf("%s: compiled to %T", p.KeyName(), ccs)
	}
	name := p.KeyName()
	constraints := r1cs.GetNbConstraints()
	levels := len(r1cs.System.Levels)
	commitments := len(ccs.GetCommitments().(constraint.Groth16Commitments).CommitmentIndexes())
	t.Logf("%s: constraints=%d levels=%d domain=2^%d commitments=%d lookup=%v compile=%s",
		name, constraints, levels, domainLog2(constraints),
		commitments, hasLookupHint(r1cs),
		time.Since(start).Round(time.Second))

	// The device route assumes one commitment and no lookup blueprint for
	// every shape. Both hold only while the emulated range checker is the
	// single commitment source.
	if commitments != 1 {
		t.Errorf("%s: commitments=%d, want 1", name, commitments)
	}
	if hasLookupHint(r1cs) {
		t.Errorf("%s: carries a lookup blueprint, which the tape exporter refuses", name)
	}

	want, pinned := wantShapes[name]
	if !pinned {
		t.Logf("%s is not pinned in wantShapes", name)
		return
	}
	if constraints != want.constraints {
		t.Errorf("%s: constraints=%d, want %d", name, constraints, want.constraints)
	}
	if levels != want.levels {
		t.Errorf("%s: levels=%d, want %d", name, levels, want.levels)
	}
}

func loadInnerSystem(t *testing.T, slot common.AggregateSlot) *common.TransferProofSystem {
	t.Helper()
	stems := map[common.CircuitType]string{
		common.TransferConfidentialCircuitType:  "transfer_confidential",
		common.TransferRingCircuitType:          "transfer_ring",
		common.TransferP256RingCircuitType:      "transfer_p256_ring",
		common.TransferRingAuthorityCircuitType: "transfer_ring_authority",
	}
	path := filepath.Join(keysDir(), fmt.Sprintf("%s_%d_%d.key", stems[slot.Inner], slot.NInputs, slot.NOutputs))
	if _, err := os.Stat(path); err != nil {
		t.Logf("skipping %s, missing %s", slot.Inner, path)
		return nil
	}
	system, err := common.ReadSystemFromFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	ps, ok := system.(*common.TransferProofSystem)
	if !ok {
		t.Fatalf("%s read as %T", path, system)
	}
	return ps
}

// domainLog2 is the log of the smallest power-of-two FFT domain that fits the
// constraint count. Crossing a boundary doubles the NTT and the Z MSM.
func domainLog2(constraints int) int {
	return bits.Len(uint(constraints - 1))
}

// hasLookupHint reports whether the compiled system carries logderivprecomp
// lookup tables. The witgen tape exporter refuses those, so a shape with them
// stays on the CPU prover until the exporter learns the blueprint.
func hasLookupHint(r1cs *cs_bn254.R1CS) bool {
	for _, blueprint := range r1cs.Blueprints {
		if _, ok := blueprint.(*constraint.BlueprintLookupHint[constraint.U32]); ok {
			return true
		}
		if _, ok := blueprint.(*constraint.BlueprintLookupHint[constraint.U64]); ok {
			return true
		}
	}
	return false
}
