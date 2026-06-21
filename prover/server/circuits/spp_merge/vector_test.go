package merge_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"zolana/prover/prover-test/poseidon"
)

// TestPrintMergeVector emits a fixed cross-language fixture for the Rust host
// (sdk-libs/keypair merge tests). The host helpers below are the same ones the
// circuit prove test validates against test.IsSolved, so this vector is the
// circuit's behavior. Inputs: tx_viewing_sk = 123456789, user viewing scalar = 7,
// plaintext = bytes 0..71.
func TestPrintMergeVector(t *testing.T) {
	curve := elliptic.P256()

	skBytes := leftPad32(big.NewInt(123456789))
	pkX, pkY := curve.ScalarBaseMult(skBytes)
	var txPkComp [33]byte
	copy(txPkComp[:], elliptic.MarshalCompressed(curve, pkX, pkY))

	viewX, viewY := curve.ScalarBaseMult(leftPad32(big.NewInt(7)))
	var rpkComp [33]byte
	copy(rpkComp[:], elliptic.MarshalCompressed(curve, viewX, viewY))

	dhX, _ := curve.ScalarMult(viewX, viewY, skBytes)
	var dh [32]byte
	dhX.FillBytes(dh[:])

	shared := deriveSharedSecret(t, dh, txPkComp, rpkComp)
	key, nonce := keySchedule(t, shared, mergeInfo)

	pt := make([]byte, 71)
	for i := range pt {
		pt[i] = byte(i)
	}
	ct := ctrEncrypt(t, key, nonce, pt)
	ctHash, err := poseidon.Hash(packBytesBE(ct, 16))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("tx_viewing_pk_comp = %x", txPkComp)
	t.Logf("shared_secret      = %x", shared.Bytes())
	t.Logf("ciphertext         = %x", ct)
	t.Logf("ciphertext_hash    = %x", ctHash.Bytes())
}
