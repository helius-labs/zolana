package transaction

import (
	"math/big"
	"strings"
	"testing"

	"light/light-prover/prover/spp/model"
	"light/light-prover/prover/spp/parse"
)

func TestDerivePublicAmountsRejectsInvalidMode(t *testing.T) {
	_, err := derivePublicAmounts(ProofTransactionRequest{PublicAmountMode: 3})
	if err == nil || !strings.Contains(err.Error(), "invalid public_amount_mode") {
		t.Fatalf("error = %v", err)
	}
}

func TestDerivePublicAmountsRejectsTransferWithPublicAmount(t *testing.T) {
	amount := uint64(1)
	_, err := derivePublicAmounts(ProofTransactionRequest{
		PublicAmountMode: 0,
		PublicSolAmount:  &amount,
	})
	if err == nil || !strings.Contains(err.Error(), "transfer mode carries public amounts") {
		t.Fatalf("error = %v", err)
	}
}

func TestDerivePublicAmountsRejectsShieldRelayerFee(t *testing.T) {
	_, err := derivePublicAmounts(ProofTransactionRequest{
		PublicAmountMode: 1,
		RelayerFee:       1,
	})
	if err == nil || !strings.Contains(err.Error(), "shield mode carries relayer fee") {
		t.Fatalf("error = %v", err)
	}
}

func TestDerivePublicAmountsSignsAmounts(t *testing.T) {
	sol := uint64(10)
	spl := uint64(7)
	amounts, err := derivePublicAmounts(ProofTransactionRequest{
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

	if amounts.sol.Cmp(model.SignedToFe(big.NewInt(-13))) != 0 {
		t.Fatalf("sol amount = %s", amounts.sol)
	}
	if amounts.spl.Cmp(model.SignedToFe(big.NewInt(-7))) != 0 {
		t.Fatalf("spl amount = %s", amounts.spl)
	}

	mint, err := parse.Hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	expectedAsset, err := model.SolanaPkHash(mint)
	if err != nil {
		t.Fatal(err)
	}
	if amounts.asset.Cmp(expectedAsset) != 0 {
		t.Fatalf("asset = %s", amounts.asset)
	}
}

func TestDerivePublicAmountsSignsTransferFeeAndShield(t *testing.T) {
	transfer, err := derivePublicAmounts(ProofTransactionRequest{
		PublicAmountMode: publicAmountTransfer,
		RelayerFee:       5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if transfer.sol.Cmp(model.SignedToFe(big.NewInt(-5))) != 0 {
		t.Fatalf("transfer sol amount = %s", transfer.sol)
	}
	if transfer.spl.Sign() != 0 {
		t.Fatalf("transfer spl amount = %s", transfer.spl)
	}

	sol := uint64(10)
	spl := uint64(7)
	shield, err := derivePublicAmounts(ProofTransactionRequest{
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
	if shield.sol.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("shield sol amount = %s", shield.sol)
	}
	if shield.spl.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("shield spl amount = %s", shield.spl)
	}
}
