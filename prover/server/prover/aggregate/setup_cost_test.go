//go:build aggregate_keys

package aggregate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
)

// TestAggregateSetupCatalogue runs trusted setup for every catalogue shape
// whose inner keys are on disk and writes the aggregate key beside them.
// Opt-in through ZOLANA_AGGREGATE_SETUP=1 because a full run is long and
// writes large key files.
//
// The swap take slot reads a raw verifying key from swap_take_vk.bin in the
// keys directory. TestTakeMixedAggregateCompiles in the swap prover module
// writes it.
func TestAggregateSetupCatalogue(t *testing.T) {
	if os.Getenv("ZOLANA_AGGREGATE_SETUP") == "" {
		t.Skip("set ZOLANA_AGGREGATE_SETUP=1 to run")
	}

	catalogue := []Params{
		Uniform(common.TransferConfidentialCircuitType, 2, 2, 2),
		Uniform(common.TransferConfidentialCircuitType, 2, 2, 3),
		Uniform(common.TransferConfidentialCircuitType, 2, 2, 4),
		Uniform(common.TransferConfidentialCircuitType, 2, 2, 5),
		Uniform(common.TransferRingCircuitType, 2, 3, 2),
		Uniform(common.TransferRingCircuitType, 2, 3, 3),
		Uniform(common.TransferP256RingCircuitType, 2, 3, 2),
		Uniform(common.TransferP256RingCircuitType, 2, 3, 3),
		{Slots: []common.AggregateSlot{confidentialSlot(), ringSlot()}},
		{Slots: []common.AggregateSlot{takeSlot(), confidentialSlot()}},
	}

	inners := map[common.AggregateSlot]*common.TransferProofSystem{}
	for _, p := range catalogue {
		vks, ok := innerKeysFor(t, inners, p)
		if !ok {
			continue
		}
		out := filepath.Join(keysDir(), p.KeyName())
		if _, err := os.Stat(out); err == nil {
			t.Logf("%s: keeping the existing key", p.KeyName())
			continue
		}

		start := time.Now()
		ps, err := SetupAggregate(p, vks)
		if err != nil {
			t.Fatalf("%s: %v", p.KeyName(), err)
		}
		setup := time.Since(start)

		file, err := os.Create(out)
		if err != nil {
			t.Fatal(err)
		}
		written, err := ps.WriteTo(file)
		if cerr := file.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatalf("%s: write: %v", p.KeyName(), err)
		}
		t.Logf("%s: constraints=%d setup=%s key=%dMB",
			p.KeyName(), ps.ConstraintSystem.GetNbConstraints(), setup.Round(time.Second), written>>20)
	}
}

func innerKeysFor(t *testing.T, cache map[common.AggregateSlot]*common.TransferProofSystem, p Params) ([]groth16.VerifyingKey, bool) {
	t.Helper()
	vks := make([]groth16.VerifyingKey, len(p.Slots))
	for i, slot := range p.Slots {
		if slot.Inner == common.SwapTakeCircuitType {
			vk, ok := loadTakeVerifyingKey(t)
			if !ok {
				return nil, false
			}
			vks[i] = vk
			continue
		}
		inner, cached := cache[slot]
		if !cached {
			inner = loadInnerSystem(t, slot)
			cache[slot] = inner
		}
		if inner == nil {
			return nil, false
		}
		vks[i] = inner.VerifyingKey
	}
	return vks, true
}

func loadTakeVerifyingKey(t *testing.T) (groth16.VerifyingKey, bool) {
	t.Helper()
	path := filepath.Join(keysDir(), "swap_take_vk.bin")
	file, err := os.Open(path)
	if err != nil {
		t.Logf("skipping the take slot, missing %s", path)
		return nil, false
	}
	defer file.Close()
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(file); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return vk, true
}
