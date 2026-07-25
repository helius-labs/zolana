package merge_test

import (
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"

	merge "zolana/prover/circuits/spp_merge"
	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"
)

// TestMergePlaintextVector pins the protocol serialization independently of the
// circuit implementation: amount (8 bytes) || asset (32 bytes) || blinding
// (31 bytes), all big-endian. The solving tests then cross-check this host
// serializer against the in-circuit serializer.
func TestMergePlaintextVector(t *testing.T) {
	out := protocol.Utxo{
		Amount:   mustBigIntHex(t, "0102030405060708"),
		Asset:    mustBigIntHex(t, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		Blinding: mustBigIntHex(t, "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e"),
	}
	const want = "0102030405060708" +
		"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
		"303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e"
	if got := hex.EncodeToString(mergePlaintext(out)); got != want {
		t.Fatalf("merge plaintext mismatch:\n got %s\nwant %s", got, want)
	}
}

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
	key, nonce := keySchedule(t, shared, []byte(merge.MergeKDFInfo))

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

func mustBigIntHex(t *testing.T, value string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("invalid hexadecimal integer %q", value)
	}
	return n
}
