package aggregate

import (
	"math/big"
	"strings"
	"testing"

	"zolana/prover/prover/common"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

func p256Params(batch uint32) Params {
	return Uniform(common.TransferP256RingCircuitType, 2, 3, batch)
}

func confidentialSlot() common.AggregateSlot {
	return common.AggregateSlot{Inner: common.TransferConfidentialCircuitType, NInputs: 2, NOutputs: 2}
}

func ringSlot() common.AggregateSlot {
	return common.AggregateSlot{Inner: common.TransferRingCircuitType, NInputs: 2, NOutputs: 3}
}

func takeSlot() common.AggregateSlot {
	return common.AggregateSlot{Inner: common.SwapTakeCircuitType}
}

// Rail codes are written into every aggregate key file. Renumbering one makes
// existing key files decode as a different rail.
func TestRailCodesAreStable(t *testing.T) {
	expected := map[common.CircuitType]uint32{
		common.TransferConfidentialCircuitType:  1,
		common.TransferRingCircuitType:          2,
		common.TransferP256RingCircuitType:      3,
		common.TransferRingAuthorityCircuitType: 4,
	}
	for rail, want := range expected {
		got, err := common.AggregatableRail(rail)
		if err != nil {
			t.Fatalf("%s: %v", rail, err)
		}
		if got != want {
			t.Errorf("%s has code %d, want %d", rail, got, want)
		}
	}
}

// Merge and address-append are not transact rails, so the shielded pool has no
// instruction that could settle a batch of them. The swap take circuit is a
// mixed-batch slot, not a rail a uniform batch can settle.
func TestNonTransactRailsAreNotAggregatable(t *testing.T) {
	for _, rail := range []common.CircuitType{
		common.MergeCircuitType,
		common.MergeRingCircuitType,
		common.BatchAddressAppendCircuitType,
		common.SwapTakeCircuitType,
		common.CircuitType("nonsense"),
	} {
		if _, err := common.AggregatableRail(rail); err == nil {
			t.Errorf("%s was accepted", rail)
		}
	}
}

func TestValidateBoundsTheBatch(t *testing.T) {
	for _, batch := range []uint32{0, 1, MaxBatch + 1} {
		if err := p256Params(batch).Validate(); err == nil {
			t.Errorf("batch %d was accepted", batch)
		}
	}
	for batch := MinBatch; batch <= MaxBatch; batch++ {
		if err := p256Params(batch).Validate(); err != nil {
			t.Errorf("batch %d was rejected: %v", batch, err)
		}
	}
}

func TestValidateRejectsAnEmptyShapeSide(t *testing.T) {
	for _, p := range []Params{
		Uniform(common.TransferRingCircuitType, 0, 3, 2),
		Uniform(common.TransferRingCircuitType, 2, 0, 2),
	} {
		if err := p.Validate(); err == nil {
			t.Error("an empty shape side was accepted")
		}
	}
}

// A take proof settles nothing on its own, so a batch of take slots alone has
// no instruction that could consume it.
func TestValidateRejectsABatchOfOnlyTakeSlots(t *testing.T) {
	p := Params{Slots: []common.AggregateSlot{takeSlot(), takeSlot()}}
	if err := p.Validate(); err == nil {
		t.Error("a batch of only take slots was accepted")
	}
}

// The take slot has no transfer shape. A shape on it would leak into the key
// name and mint distinct keys for one circuit.
func TestValidateRejectsATakeSlotWithAShape(t *testing.T) {
	p := Params{Slots: []common.AggregateSlot{
		{Inner: common.SwapTakeCircuitType, NInputs: 2, NOutputs: 3},
		confidentialSlot(),
	}}
	if err := p.Validate(); err == nil {
		t.Error("a take slot with a shape was accepted")
	}
}

func TestMixedParamsValidate(t *testing.T) {
	for _, p := range []Params{
		{Slots: []common.AggregateSlot{takeSlot(), confidentialSlot()}},
		{Slots: []common.AggregateSlot{confidentialSlot(), ringSlot()}},
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("%s was rejected: %v", p.KeyName(), err)
		}
	}
}

// common.ReadSystemFromFile picks a header by substring, and an aggregate name
// also contains the rail it batches. The aggregate branch runs first, so the
// name must carry "aggregate" for that branch to claim it.
func TestKeyNameLeadsWithAggregate(t *testing.T) {
	name := p256Params(3).KeyName()
	if name != "aggregate_transfer_p256_ring_2_3_b3.key" {
		t.Fatalf("key name is %q", name)
	}
	if !strings.HasPrefix(name, "aggregate") {
		t.Errorf("%q would be read with the transfer header", name)
	}
	if !strings.Contains(name, "transfer") {
		t.Errorf("%q does not name the rail it batches", name)
	}
}

// Mixed key names list the slots in order. The statement binds slot order, so
// two orders are two proving systems and must not share a file.
func TestMixedKeyNamesEncodeSlotOrder(t *testing.T) {
	takeFirst := Params{Slots: []common.AggregateSlot{takeSlot(), confidentialSlot()}}
	if name := takeFirst.KeyName(); name != "aggregate_mix_swap_take-transfer_confidential_2_2_b2.key" {
		t.Fatalf("key name is %q", name)
	}
	confidentialFirst := Params{Slots: []common.AggregateSlot{confidentialSlot(), takeSlot()}}
	if takeFirst.KeyName() == confidentialFirst.KeyName() {
		t.Error("two slot orders share a key name")
	}

	pair := Params{Slots: []common.AggregateSlot{confidentialSlot(), ringSlot()}}
	if name := pair.KeyName(); name != "aggregate_mix_transfer_confidential_2_2-transfer_ring_2_3_b2.key" {
		t.Fatalf("key name is %q", name)
	}
}

func TestKeyNamesAreDistinctPerSystem(t *testing.T) {
	seen := map[string]struct{}{}
	for _, rail := range []common.CircuitType{
		common.TransferConfidentialCircuitType,
		common.TransferRingCircuitType,
		common.TransferP256RingCircuitType,
		common.TransferRingAuthorityCircuitType,
	} {
		for batch := MinBatch; batch <= MaxBatch; batch++ {
			name := Uniform(rail, 2, 3, batch).KeyName()
			if _, clash := seen[name]; clash {
				t.Fatalf("%q is reused", name)
			}
			seen[name] = struct{}{}
		}
	}
}

// The chain must match the outer circuit and the shielded pool. Both fold left,
// so the order of the legs is part of the statement.
func TestAggregateInputHashFoldsLeft(t *testing.T) {
	legs := []*big.Int{big.NewInt(11), big.NewInt(22), big.NewInt(33)}

	got, err := AggregateInputHash(legs)
	if err != nil {
		t.Fatal(err)
	}

	first, err := poseidon.Hash([]*big.Int{legs[0], legs[1]})
	if err != nil {
		t.Fatal(err)
	}
	want, err := poseidon.Hash([]*big.Int{first, legs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(want) != 0 {
		t.Errorf("chain is %s, want %s", got, want)
	}
}

func TestAggregateInputHashIsOrderSensitive(t *testing.T) {
	forward, err := AggregateInputHash([]*big.Int{big.NewInt(11), big.NewInt(22)})
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := AggregateInputHash([]*big.Int{big.NewInt(22), big.NewInt(11)})
	if err != nil {
		t.Fatal(err)
	}
	if forward.Cmp(reversed) == 0 {
		t.Error("a reordered batch produces the same chain")
	}
}

func TestAggregateInputHashRejectsAnEmptyBatch(t *testing.T) {
	if _, err := AggregateInputHash(nil); err == nil {
		t.Error("empty batch was accepted")
	}
}
