package transaction

import (
	"math/big"
	"strings"
	"testing"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

func TestDerivePublicSlotsRejectsInvalidMode(t *testing.T) {
	_, err := derivePublicSlots(ProofTransactionRequest{PublicAmountMode: 3})
	if err == nil || !strings.Contains(err.Error(), "invalid public_amount_mode") {
		t.Fatalf("error = %v", err)
	}
}

func TestDerivePublicSlotsRejectsTransferWithPublicAmount(t *testing.T) {
	amount := uint64(1)
	_, err := derivePublicSlots(ProofTransactionRequest{
		PublicAmountMode: 0,
		PublicSolAmount:  &amount,
	})
	if err == nil || !strings.Contains(err.Error(), "transfer mode carries public settlement") {
		t.Fatalf("error = %v", err)
	}
}

func TestDerivePublicSlotsRejectsTransferRelayerFee(t *testing.T) {
	_, err := derivePublicSlots(ProofTransactionRequest{
		PublicAmountMode: publicAmountTransfer,
		RelayerFee:       5,
	})
	if err == nil || !strings.Contains(err.Error(), "transfer mode carries public settlement") {
		t.Fatalf("error = %v", err)
	}
}

func TestDerivePublicSlotsRejectsShieldRelayerFee(t *testing.T) {
	_, err := derivePublicSlots(ProofTransactionRequest{
		PublicAmountMode: 1,
		RelayerFee:       1,
	})
	if err == nil || !strings.Contains(err.Error(), "shield mode carries relayer fee") {
		t.Fatalf("error = %v", err)
	}
}

func TestDerivePublicSlotsSignsAmounts(t *testing.T) {
	sol := uint64(10)
	spl := uint64(7)
	slots, err := derivePublicSlots(ProofTransactionRequest{
		PublicAmountMode: 2,
		PublicSolAmount:  &sol,
		PublicSplAmount:  &spl,
		RelayerFee:       3,
		PublicSplAssetPubkey: "" +
			"000102030405060708090a0b0c0d0e0f" +
			"101112131415161718191a1b1c1d1e1f",
	})
	if err != nil {
		t.Fatal(err)
	}

	if slots.amounts[0].Cmp(protocol.SignedToField(big.NewInt(-13))) != 0 {
		t.Fatalf("sol slot amount = %s", slots.amounts[0])
	}
	if slots.assets[0].Cmp(protocol.SolAsset()) != 0 {
		t.Fatalf("sol slot asset = %s", slots.assets[0])
	}
	if slots.amounts[1].Cmp(protocol.SignedToField(big.NewInt(-7))) != 0 {
		t.Fatalf("spl slot amount = %s", slots.amounts[1])
	}

	mint, err := parse.Hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	expectedAsset, err := protocol.SolanaPkField(mint)
	if err != nil {
		t.Fatal(err)
	}
	if slots.assets[1].Cmp(expectedAsset) != 0 {
		t.Fatalf("spl slot asset = %s", slots.assets[1])
	}
}

func TestDerivePublicSlotsSignsShield(t *testing.T) {
	sol := uint64(10)
	spl := uint64(7)
	shield, err := derivePublicSlots(ProofTransactionRequest{
		PublicAmountMode: publicAmountShield,
		PublicSolAmount:  &sol,
		PublicSplAmount:  &spl,
		PublicSplAssetPubkey: "" +
			"000102030405060708090a0b0c0d0e0f" +
			"101112131415161718191a1b1c1d1e1f",
	})
	if err != nil {
		t.Fatal(err)
	}
	if shield.amounts[0].Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("shield sol slot amount = %s", shield.amounts[0])
	}
	if shield.assets[0].Cmp(protocol.SolAsset()) != 0 {
		t.Fatalf("shield sol slot asset = %s", shield.assets[0])
	}
	if shield.amounts[1].Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("shield spl slot amount = %s", shield.amounts[1])
	}
}

// Pure transfers keep every slot at (0, 0) so the transcript reveals no asset id.
func TestDerivePublicSlotsTransferKeepsSlotsIdle(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{PublicAmountMode: publicAmountTransfer})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < protocol.NPublicSlots; i++ {
		if slots.assets[i].Sign() != 0 || slots.amounts[i].Sign() != 0 {
			t.Fatalf("slot %d = (%s, %s), want (0, 0)", i, slots.assets[i], slots.amounts[i])
		}
	}
}

// A fee-only unshield has no request SOL amount but still moves SOL: the
// SOL slot must carry the SolAsset id, or the circuit's slot pinning fails.
func TestDerivePublicSlotsFeeOnlyUnshieldActivatesSolSlot(t *testing.T) {
	slots, err := derivePublicSlots(ProofTransactionRequest{
		PublicAmountMode: publicAmountUnshield,
		RelayerFee:       3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if slots.amounts[0].Cmp(protocol.SignedToField(big.NewInt(-3))) != 0 {
		t.Fatalf("sol slot amount = %s", slots.amounts[0])
	}
	if slots.assets[0].Cmp(protocol.SolAsset()) != 0 {
		t.Fatalf("sol slot asset = %s", slots.assets[0])
	}
	if slots.assets[1].Sign() != 0 || slots.amounts[1].Sign() != 0 {
		t.Fatalf("spl slot = (%s, %s), want (0, 0)", slots.assets[1], slots.amounts[1])
	}
}
