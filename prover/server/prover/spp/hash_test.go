package spp

import (
	"math/big"
	"testing"

	"light/light-prover/prover/poseidon"
)

func fe(v int64) *big.Int {
	return big.NewInt(v)
}

func mustHash(t *testing.T, value *big.Int, err error) *big.Int {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected hash error: %v", err)
	}
	return value
}

func mustUtxoHash(t *testing.T, utxo Utxo) *big.Int {
	t.Helper()
	value, err := UtxoHash(utxo)
	return mustHash(t, value, err)
}

func mustPoseidon(t *testing.T, width int, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := poseidon.HashWithT(width, inputs)
	return mustHash(t, value, err)
}

func mustPreNullifier(t *testing.T, blinding, secret *big.Int) *big.Int {
	t.Helper()
	value, err := PreNullifier(blinding, secret)
	return mustHash(t, value, err)
}

func mustNullifierHash(t *testing.T, utxoHash, preNullifier *big.Int) *big.Int {
	t.Helper()
	value, err := NullifierHash(utxoHash, preNullifier)
	return mustHash(t, value, err)
}

func mustNullifierFromSecret(t *testing.T, utxo Utxo, secret *big.Int) *big.Int {
	t.Helper()
	value, err := NullifierFromSecret(utxo, secret)
	return mustHash(t, value, err)
}

func mustHashChain(t *testing.T, inputs []*big.Int) *big.Int {
	t.Helper()
	value, err := HashChain(inputs)
	return mustHash(t, value, err)
}

func mustPrivateTxHash(t *testing.T, inputs, outputs []*big.Int, externalDataHash, expiry *big.Int) *big.Int {
	t.Helper()
	value, err := PrivateTxHash(inputs, outputs, externalDataHash, expiry)
	return mustHash(t, value, err)
}

func TestUtxoHashUsesSpecFieldOrder(t *testing.T) {
	utxo := Utxo{
		Domain:          fe(1),
		Owner:           fe(2),
		AssetID:         fe(3),
		AssetAmount:     fe(4),
		Blinding:        fe(5),
		DataHash:        fe(6),
		PolicyData:      fe(7),
		PolicyProgramID: fe(8),
	}

	got := mustUtxoHash(t, utxo)
	want := mustPoseidon(t, 9, []*big.Int{
		fe(1), fe(2), fe(3), fe(4), fe(5), fe(6), fe(7), fe(8),
	})
	if got.Cmp(want) != 0 {
		t.Fatalf("utxo hash mismatch: got %s want %s", got, want)
	}

	swapped := mustPoseidon(t, 9, []*big.Int{
		fe(1), fe(2), fe(4), fe(3), fe(5), fe(6), fe(7), fe(8),
	})
	if got.Cmp(swapped) == 0 {
		t.Fatal("utxo hash did not change when asset_id and asset_amount were swapped")
	}
}

func TestNullifierMatchesSpecFormula(t *testing.T) {
	utxo := sampleUtxo(10)
	utxoHash := mustUtxoHash(t, utxo)
	secret := fe(99)

	preNullifier := mustPreNullifier(t, utxo.Blinding, secret)
	wantPreNullifier := mustPoseidon(t, 3, []*big.Int{utxo.Blinding, secret})
	if preNullifier.Cmp(wantPreNullifier) != 0 {
		t.Fatalf("pre-nullifier mismatch: got %s want %s", preNullifier, wantPreNullifier)
	}

	nullifier := mustNullifierHash(t, utxoHash, preNullifier)
	wantNullifier := mustPoseidon(t, 3, []*big.Int{utxoHash, preNullifier})
	if nullifier.Cmp(wantNullifier) != 0 {
		t.Fatalf("nullifier mismatch: got %s want %s", nullifier, wantNullifier)
	}

	other := mustNullifierFromSecret(t, utxo, fe(100))
	if nullifier.Cmp(other) == 0 {
		t.Fatal("nullifier did not change when nullifier secret changed")
	}
}

func TestHashChainRightFold(t *testing.T) {
	inputs := []*big.Int{fe(1), fe(2), fe(3)}

	got := mustHashChain(t, inputs)
	inner := mustPoseidon(t, 3, []*big.Int{fe(2), fe(3)})
	want := mustPoseidon(t, 3, []*big.Int{fe(1), inner})
	if got.Cmp(want) != 0 {
		t.Fatalf("right-fold mismatch: got %s want %s", got, want)
	}

	leftInner := mustPoseidon(t, 3, []*big.Int{fe(1), fe(2)})
	leftFold := mustPoseidon(t, 3, []*big.Int{leftInner, fe(3)})
	if got.Cmp(leftFold) == 0 {
		t.Fatal("hash chain unexpectedly matched left-fold result")
	}
}

func TestHashChainEmptyAndSingle(t *testing.T) {
	empty := mustHashChain(t, nil)
	if empty.Sign() != 0 {
		t.Fatalf("empty hash chain should be zero, got %s", empty)
	}

	single := mustHashChain(t, []*big.Int{fe(123)})
	if single.Cmp(fe(123)) != 0 {
		t.Fatalf("single hash chain should return the input, got %s", single)
	}
}

func TestPrivateTxHashMatchesSpecFormula(t *testing.T) {
	inputs := []*big.Int{fe(11), fe(12)}
	outputs := []*big.Int{fe(21), fe(22)}
	externalDataHash := fe(31)
	expiry := fe(41)

	got := mustPrivateTxHash(t, inputs, outputs, externalDataHash, expiry)
	inputChain := mustHashChain(t, inputs)
	outputChain := mustHashChain(t, outputs)
	want := mustPoseidon(t, 5, []*big.Int{
		inputChain,
		outputChain,
		externalDataHash,
		expiry,
	})
	if got.Cmp(want) != 0 {
		t.Fatalf("private tx hash mismatch: got %s want %s", got, want)
	}

	changedExpiry := mustPrivateTxHash(t, inputs, outputs, externalDataHash, fe(42))
	if got.Cmp(changedExpiry) == 0 {
		t.Fatal("private tx hash did not change when expiry changed")
	}
}

func TestHashRejectsInvalidFieldElements(t *testing.T) {
	if _, err := HashChain([]*big.Int{nil}); err == nil {
		t.Fatal("expected nil hash-chain input to fail")
	}
	if _, err := HashChain([]*big.Int{new(big.Int).Set(poseidon.Modulus)}); err == nil {
		t.Fatal("expected modulus-sized hash-chain input to fail")
	}
	if _, err := UtxoHash(Utxo{}); err == nil {
		t.Fatal("expected nil utxo fields to fail")
	}
}
