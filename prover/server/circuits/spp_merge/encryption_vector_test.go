package merge_test

import (
	"crypto/elliptic"
	"encoding/hex"
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

	fixtures := []struct {
		name string
		got  []byte
		want string
	}{
		{
			name: "tx viewing public key",
			got:  txPkComp[:],
			want: "02fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003eac8",
		},
		{
			name: "shared secret",
			got:  leftPad32(shared),
			want: "0ffef3a9547f8b4112f81b60595410996a6a4844372204d43be44f06a13cc4ca",
		},
		{
			name: "ciphertext",
			got:  ct,
			want: "d52cccc7053c653d83c840fcb12c3a1dd6ac2263a9f4c705d784dfd894234b6b5271590160bddbb7191a0eeb96646aa5397e0acb27b605aec6f1ceadcd2726cab1a675d511f202",
		},
		{
			name: "ciphertext hash",
			got:  leftPad32(ctHash),
			want: "2418c4f8d103a80bcc365a28f6172e7cd9cbfe71a301c19f775a64187ed2f453",
		},
	}
	for _, fixture := range fixtures {
		if got := hex.EncodeToString(fixture.got); got != fixture.want {
			t.Errorf("%s mismatch:\n got %s\nwant %s", fixture.name, got, fixture.want)
		}
	}

	t.Logf("tx_viewing_pk_comp = %x", txPkComp)
	t.Logf("shared_secret      = %x", shared.Bytes())
	t.Logf("ciphertext         = %x", ct)
	t.Logf("ciphertext_hash    = %x", ctHash.Bytes())
}
