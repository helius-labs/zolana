package transaction

import (
	"math"
	"math/big"
	"strings"
	"testing"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

const (
	testMintA = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	testMintB = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	testMintC = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
)

func TestDerivePublicSlotsKeepsEmptySlotsIdle(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range slots.assets {
		expectIdleSlot(t, slots, i)
	}
}

func TestDerivePublicSlotsSingleSplUsesSlotZero(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{
		InterfaceTransfers: []InterfaceTransferRequest{{
			IsSpl: true, IsDeposit: true, Asset: testMintA, Amount: 17,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectSplAsset(t, slots.assets[0], testMintA)
	expectSignedAmount(t, slots.amounts[0], true, 17)
	expectIdleSlot(t, slots, 1)
	expectIdleSlot(t, slots, 2)
}

func TestDerivePublicSlotsAggregatesMixedDirectionsByFirstAppearance(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{
		InterfaceTransfers: []InterfaceTransferRequest{
			{IsSpl: true, IsDeposit: true, Asset: testMintA, Amount: 11},
			{Amount: 8},
			{IsSpl: true, Asset: testMintA, Amount: 6},
			{IsDeposit: true, Amount: 3},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectSplAsset(t, slots.assets[0], testMintA)
	expectSignedAmount(t, slots.amounts[0], true, 5)
	if slots.assets[1].Cmp(protocol.SolAsset()) != 0 {
		t.Fatalf("SOL asset = %s", slots.assets[1])
	}
	expectSignedAmount(t, slots.amounts[1], false, 5)
	expectIdleSlot(t, slots, 2)
}

func TestDerivePublicSlotsAcceptsSixSameAssetLegs(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{
		InterfaceTransfers: []InterfaceTransferRequest{
			{IsSpl: true, IsDeposit: true, Asset: testMintA, Amount: 10},
			{IsSpl: true, Asset: testMintA, Amount: 2},
			{IsSpl: true, IsDeposit: true, Asset: testMintA, Amount: 7},
			{IsSpl: true, Asset: testMintA, Amount: 4},
			{IsSpl: true, IsDeposit: true, Asset: testMintA, Amount: 1},
			{IsSpl: true, Asset: testMintA, Amount: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectSplAsset(t, slots.assets[0], testMintA)
	expectSignedAmount(t, slots.amounts[0], true, 11)
	expectIdleSlot(t, slots, 1)
	expectIdleSlot(t, slots, 2)
}

func TestDerivePublicSlotsAcceptsU8TransferCountBoundary(t *testing.T) {
	transfers := make([]InterfaceTransferRequest, MaxInterfaceTransfers)
	for i := range transfers {
		transfers[i] = InterfaceTransferRequest{IsDeposit: true, Amount: 1}
	}
	slots, err := derivePublicSlots(ProofTransactionRequest{InterfaceTransfers: transfers})
	if err != nil {
		t.Fatal(err)
	}
	if slots.assets[0].Cmp(protocol.SolAsset()) != 0 {
		t.Fatalf("SOL asset = %s", slots.assets[0])
	}
	expectSignedAmount(t, slots.amounts[0], true, MaxInterfaceTransfers)
	expectIdleSlot(t, slots, 1)
	expectIdleSlot(t, slots, 2)
}

func TestDerivePublicSlotsAcceptsThreeDistinctAssets(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{
		InterfaceTransfers: []InterfaceTransferRequest{
			{IsSpl: true, Asset: testMintB, Amount: 9},
			{IsDeposit: true, Amount: 4},
			{IsSpl: true, IsDeposit: true, Asset: testMintA, Amount: 7},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectSplAsset(t, slots.assets[0], testMintB)
	expectSignedAmount(t, slots.amounts[0], false, 9)
	if slots.assets[1].Cmp(protocol.SolAsset()) != 0 {
		t.Fatalf("SOL asset = %s", slots.assets[1])
	}
	expectSignedAmount(t, slots.amounts[1], true, 4)
	expectSplAsset(t, slots.assets[2], testMintA)
	expectSignedAmount(t, slots.amounts[2], true, 7)
}

func TestDerivePublicSlotsNetZeroAssetsDoNotConsumeSlots(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{
		InterfaceTransfers: []InterfaceTransferRequest{
			{IsDeposit: true, Amount: 5},
			{IsSpl: true, IsDeposit: true, Asset: testMintA, Amount: 2},
			{IsSpl: true, IsDeposit: true, Asset: testMintB, Amount: 3},
			{IsSpl: true, IsDeposit: true, Asset: testMintC, Amount: 4},
			{Amount: 5},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectSplAsset(t, slots.assets[0], testMintA)
	expectSplAsset(t, slots.assets[1], testMintB)
	expectSplAsset(t, slots.assets[2], testMintC)
	expectSignedAmount(t, slots.amounts[0], true, 2)
	expectSignedAmount(t, slots.amounts[1], true, 3)
	expectSignedAmount(t, slots.amounts[2], true, 4)
}

func TestDerivePublicSlotsSupportsFullU64Bounds(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{
		InterfaceTransfers: []InterfaceTransferRequest{
			{IsDeposit: true, Amount: math.MaxUint64},
			{IsSpl: true, Asset: testMintA, Amount: math.MaxUint64},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectSignedAmount(t, slots.amounts[0], true, math.MaxUint64)
	expectSignedAmount(t, slots.amounts[1], false, math.MaxUint64)
	expectIdleSlot(t, slots, 2)
}

func TestDerivePublicSlotsRejectsAggregateOverflow(t *testing.T) {
	tests := []struct {
		name      string
		transfers []InterfaceTransferRequest
	}{
		{
			name: "positive",
			transfers: []InterfaceTransferRequest{
				{IsDeposit: true, Amount: math.MaxUint64},
				{IsDeposit: true, Amount: 1},
			},
		},
		{
			name:      "negative",
			transfers: []InterfaceTransferRequest{{Amount: math.MaxUint64}, {Amount: 1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := derivePublicSlots(ProofTransactionRequest{InterfaceTransfers: tt.transfers})
			if err == nil || !strings.Contains(err.Error(), "aggregate magnitude exceeds u64") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDerivePublicSlotsChecksFinalNetMagnitude(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{
		InterfaceTransfers: []InterfaceTransferRequest{
			{IsDeposit: true, Amount: math.MaxUint64},
			{IsDeposit: true, Amount: math.MaxUint64},
			{Amount: math.MaxUint64},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectSignedAmount(t, slots.amounts[0], true, math.MaxUint64)
}

func TestDerivePublicSlotsRejectsInvalidInterfaceTransfers(t *testing.T) {
	tooManyTransfers := make([]InterfaceTransferRequest, MaxInterfaceTransfers+1)
	for i := range tooManyTransfers {
		tooManyTransfers[i].Amount = 1
	}
	tests := []struct {
		name      string
		transfers []InterfaceTransferRequest
		wantErr   string
	}{
		{
			name:      "transfer count exceeds protocol maximum",
			transfers: tooManyTransfers,
			wantErr:   "interface_transfers length 33 exceeds protocol maximum 32",
		},
		{
			name:      "zero amount",
			transfers: []InterfaceTransferRequest{{Amount: 0}},
			wantErr:   "interface_transfers[0].amount must be nonzero",
		},
		{
			name:      "missing SPL asset",
			transfers: []InterfaceTransferRequest{{IsSpl: true, Amount: 1}},
			wantErr:   "interface_transfers[0].asset",
		},
		{
			name:      "SOL asset",
			transfers: []InterfaceTransferRequest{{Asset: testMintA, Amount: 1}},
			wantErr:   "asset must be empty for SOL",
		},
		{
			name: "four distinct nonzero assets",
			transfers: []InterfaceTransferRequest{
				{Amount: 1},
				{IsSpl: true, Asset: testMintA, Amount: 2},
				{IsSpl: true, Asset: testMintB, Amount: 3},
				{IsSpl: true, Asset: testMintC, Amount: 4},
			},
			wantErr: "aggregate to more than 3 distinct nonzero assets",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := derivePublicSlots(ProofTransactionRequest{InterfaceTransfers: tt.transfers})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func expectSplAsset(t *testing.T, got *big.Int, mintHex string) {
	t.Helper()
	mint, err := parse.Hex32(mintHex)
	if err != nil {
		t.Fatal(err)
	}
	want, err := protocol.SolanaPkField(mint)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("SPL asset = %s, want %s", got, want)
	}
}

func expectSignedAmount(t *testing.T, got *big.Int, isDeposit bool, amount uint64) {
	t.Helper()
	want := new(big.Int).SetUint64(amount)
	if !isDeposit {
		want.Neg(want)
	}
	want = protocol.SignedToField(want)
	if got.Cmp(want) != 0 {
		t.Fatalf("amount = %s, want %s", got, want)
	}
}

func expectIdleSlot(t *testing.T, slots publicSlots, index int) {
	t.Helper()
	if slots.assets[index].Sign() != 0 || slots.amounts[index].Sign() != 0 {
		t.Fatalf("slot %d = (%s, %s), want (0, 0)", index, slots.assets[index], slots.amounts[index])
	}
}
