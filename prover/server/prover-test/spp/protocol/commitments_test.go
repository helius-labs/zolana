package protocol

import (
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"

	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/internal/p256key"
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

func mustNullifierPk(t *testing.T, secret *big.Int) *big.Int {
	t.Helper()
	value, err := NullifierPk(secret)
	return mustHash(t, value, err)
}

func mustOwnerHash(t *testing.T, ownerKeyHash, nullifierPk *big.Int) *big.Int {
	t.Helper()
	value, err := OwnerHash(ownerKeyHash, nullifierPk)
	return mustHash(t, value, err)
}

func mustSolanaPkField(t *testing.T, pubkey [32]byte) *big.Int {
	t.Helper()
	value, err := SolanaPkField(pubkey)
	return mustHash(t, value, err)
}

func mustNullifier(t *testing.T, utxoHash, blinding, secret *big.Int) *big.Int {
	t.Helper()
	value, err := Nullifier(utxoHash, blinding, secret)
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

func mustPrivateTxHash(t *testing.T, inputs, outputs, addresses []*big.Int, externalDataHash *big.Int) *big.Int {
	t.Helper()
	value, err := PrivateTxHash(inputs, outputs, addresses, externalDataHash)
	return mustHash(t, value, err)
}

func TestUtxoHashUsesSpecFieldOrder(t *testing.T) {
	utxo := Utxo{
		Domain:        fe(1),
		Owner:         fe(2),
		Asset:         fe(3),
		Amount:        fe(4),
		Blinding:      fe(5),
		DataHash:      fe(6),
		ZoneDataHash:  fe(7),
		ZoneProgramID: fe(8),
	}

	got := mustUtxoHash(t, utxo)
	ownerUtxoHash := mustPoseidon(t, 3, []*big.Int{fe(2), fe(5)})
	zoneHash := mustPoseidon(t, 3, []*big.Int{fe(7), fe(8)})
	want := mustPoseidon(t, 7, []*big.Int{
		fe(1), fe(3), fe(4), fe(6), zoneHash, ownerUtxoHash,
	})
	if got.Cmp(want) != 0 {
		t.Fatalf("utxo hash mismatch: got %s want %s", got, want)
	}

	swapped := mustPoseidon(t, 7, []*big.Int{
		fe(1), fe(4), fe(3), fe(6), zoneHash, ownerUtxoHash,
	})
	if got.Cmp(swapped) == 0 {
		t.Fatal("utxo hash did not change when asset_id and asset_amount were swapped")
	}
}

func TestNullifierMatchesSpecFormula(t *testing.T) {
	utxo := sampleUtxo(10)
	utxoHash := mustUtxoHash(t, utxo)
	secret := fe(99)

	nullifierPk := mustNullifierPk(t, secret)
	wantNullifierPk := mustPoseidon(t, 2, []*big.Int{secret})
	if nullifierPk.Cmp(wantNullifierPk) != 0 {
		t.Fatalf("nullifier pk mismatch: got %s want %s", nullifierPk, wantNullifierPk)
	}

	nullifier := mustNullifier(t, utxoHash, utxo.Blinding, secret)
	// spec: nullifier := Poseidon(utxo_hash, utxo_blinding, nullifier_secret)
	wantNullifier := mustPoseidon(t, 4, []*big.Int{utxoHash, utxo.Blinding, secret})
	if nullifier.Cmp(wantNullifier) != 0 {
		t.Fatalf("nullifier mismatch: got %s want %s", nullifier, wantNullifier)
	}
	if !InNullifierDomain(nullifier) {
		t.Fatalf("nullifier outside the tree domain: %s", nullifier)
	}

	other := mustNullifierFromSecret(t, utxo, fe(100))
	if nullifier.Cmp(other) == 0 {
		t.Fatal("nullifier did not change when nullifier secret changed")
	}
}

func TestOwnerHashMatchesSpecFormula(t *testing.T) {
	ownerKeyHash := fe(12)
	nullifierPk := fe(13)
	got := mustOwnerHash(t, ownerKeyHash, nullifierPk)
	want := mustPoseidon(t, 3, []*big.Int{ownerKeyHash, nullifierPk})
	if got.Cmp(want) != 0 {
		t.Fatalf("owner hash mismatch: got %s want %s", got, want)
	}
}

func TestSolanaPkFieldMatchesSpecFormula(t *testing.T) {
	var pubkey [32]byte
	for i := range pubkey {
		pubkey[i] = byte(i + 1)
	}
	got := mustSolanaPkField(t, pubkey)
	want := mustPoseidon(t, 3, []*big.Int{
		new(big.Int).SetBytes(pubkey[16:]),
		new(big.Int).SetBytes(pubkey[:16]),
	})
	if got.Cmp(want) != 0 {
		t.Fatalf("solana pk hash mismatch: got %s want %s", got, want)
	}
}

func TestP256PkFieldMatchesSpecFormula(t *testing.T) {
	priv, err := p256key.PrivateKeyFromScalar(big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	got, err := P256PkField(compressed)
	if err != nil {
		t.Fatal(err)
	}
	var xBytes [32]byte
	priv.PublicKey.X.FillBytes(xBytes[:])
	xHash := mustPoseidon(t, 3, []*big.Int{
		new(big.Int).SetBytes(xBytes[16:]),
		new(big.Int).SetBytes(xBytes[:16]),
	})
	want := mustPoseidon(t, 3, []*big.Int{
		new(big.Int).SetUint64(uint64(compressed[0] & 1)),
		xHash,
	})
	if got.Cmp(want) != 0 {
		t.Fatalf("P256 owner key hash mismatch: got %s want %s", got, want)
	}
}

func TestP256MessageDigestIsFullSha256(t *testing.T) {
	privateTxHash := new(big.Int).SetBytes([]byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c,
		0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c,
		0x1d, 0x1e, 0x1f, 0x20,
	})

	digest, err := P256MessageDigest(privateTxHash)
	if err != nil {
		t.Fatalf("p256 message digest: %v", err)
	}
	var privateTxHashBytes [32]byte
	privateTxHash.FillBytes(privateTxHashBytes[:])
	// Full SHA-256, no byte zeroing: the digest is carried as two 128-bit limbs.
	want := sha256.Sum256(privateTxHashBytes[:])
	if digest != want {
		t.Fatalf("p256 message digest mismatch: got %x want %x", digest, want)
	}

	// Limbs are the big-endian high/low halves and reconstruct the digest.
	low, high := P256MessageLimbs(digest)
	wantHigh := new(big.Int).SetBytes(want[0:16])
	wantLow := new(big.Int).SetBytes(want[16:32])
	if low.Cmp(wantLow) != 0 || high.Cmp(wantHigh) != 0 {
		t.Fatalf("p256 message limbs mismatch: got (%s,%s) want (%s,%s)", low, high, wantLow, wantHigh)
	}
}

func TestHashChainLeftFold(t *testing.T) {
	inputs := []*big.Int{fe(1), fe(2), fe(3)}

	got := mustHashChain(t, inputs)
	inner := mustPoseidon(t, 3, []*big.Int{fe(1), fe(2)})
	want := mustPoseidon(t, 3, []*big.Int{inner, fe(3)})
	if got.Cmp(want) != 0 {
		t.Fatalf("left-fold mismatch: got %s want %s", got, want)
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
	addresses := []*big.Int{fe(41), fe(42)}
	externalDataHash := fe(31)

	// expiry_unix_ts is NOT a private_tx_hash input — it is bound through
	// external_data_hash (tested in the prover's external_data tests).
	got := mustPrivateTxHash(t, inputs, outputs, addresses, externalDataHash)
	inputChain := mustHashChain(t, inputs)
	outputChain := mustHashChain(t, outputs)
	addressChain := mustHashChain(t, addresses)
	want := mustPoseidon(t, 5, []*big.Int{
		inputChain,
		outputChain,
		addressChain,
		externalDataHash,
	})
	if got.Cmp(want) != 0 {
		t.Fatalf("private tx hash mismatch: got %s want %s", got, want)
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
