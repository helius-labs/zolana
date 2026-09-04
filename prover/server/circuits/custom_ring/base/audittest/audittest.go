// Package audittest recomputes the audit block of package base on the host.
package audittest

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	base "zolana/prover/circuits/custom_ring/base"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

// Mirrors the unexported key-schedule info string of package base.
const auditEncInfo = "CRING/adt1"

type Keys struct {
	txSk      [32]byte
	ephSk     [32]byte
	txPk      [33]byte
	ephPk     [33]byte
	auditorPk [65]byte
	dh        [32]byte
}

func DefaultKeys(t testing.TB) Keys {
	t.Helper()
	txSk := Scalar(0x11)
	ephSk := Scalar(0x22)
	txPriv := PrivateKey(t, txSk)
	ephPriv := PrivateKey(t, ephSk)
	auditorPriv := PrivateKey(t, Scalar(0x33))

	dh, err := ephPriv.ECDH(auditorPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return Keys{
		txSk:      txSk,
		ephSk:     ephSk,
		txPk:      compress(t, txPriv.PublicKey().Bytes()),
		ephPk:     compress(t, ephPriv.PublicKey().Bytes()),
		auditorPk: Uncompressed(t, auditorPriv.PublicKey().Bytes()),
		dh:        [32]byte(dh),
	}
}

// The gadget compresses its (0,0) infinity to 0x02||0^32.
var infinityPk = [33]byte{0x02}

func (k Keys) WithInfinityTxScalar(value *big.Int) Keys {
	value.FillBytes(k.txSk[:])
	k.txPk = infinityPk
	return k
}

func (k Keys) WithInfinityEphScalar(value *big.Int) Keys {
	value.FillBytes(k.ephSk[:])
	k.ephPk = infinityPk
	k.dh = [32]byte{}
	return k
}

func (k Keys) AuditBlockWires(privateTxHash *big.Int) base.AuditBlockWires {
	w := base.AuditBlockWires{PrivateTxHash: privateTxHash}
	setBytes(w.TxViewingSk[:], k.txSk[:])
	setBytes(w.EphSk[:], k.ephSk[:])
	setBytes(w.AuditorPk[:], k.auditorPk[:])
	return w
}

// Chain elements 1 to 8 of package base.
func (k Keys) ChainElements(t testing.TB, privateTxHash *big.Int) []*big.Int {
	t.Helper()
	dhLo, dhHi := pack32(k.dh)
	txLo, txHi := pack33(k.txPk)
	ephLo, ephHi := pack33(k.ephPk)
	auditorLo, auditorHi := pack33(compress(t, k.auditorPk[:]))

	sharedSecret := spptest.MustPoseidon(t, 8, []*big.Int{
		tag(base.DomSepCRShared),
		dhLo, dhHi,
		ephLo, ephHi,
		auditorLo, auditorHi,
	})
	key, nonce := keySchedule(t, sharedSecret)
	ciphertext, err := protocol.HashBytes(ctrEncrypt(t, key, nonce, k.txSk[:]))
	ciphertextHash := spptest.MustHash(t, ciphertext, err)

	return []*big.Int{
		privateTxHash,
		txLo, txHi,
		auditorLo, auditorHi,
		ephLo, ephHi,
		ciphertextHash,
	}
}

// The leading 0x01 keeps every seed below the group order.
func Scalar(seed byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	out[0] = 0x01
	return out
}

func PrivateKey(t testing.TB, scalar [32]byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	return key
}

func Uncompressed(t testing.TB, publicKey []byte) [65]byte {
	t.Helper()
	if len(publicKey) != 65 {
		t.Fatalf("expected a 65-byte uncompressed key, got %d bytes", len(publicKey))
	}
	var out [65]byte
	copy(out[:], publicKey)
	if out[0] != 4 {
		t.Fatalf("expected the 0x04 prefix, got %#x", out[0])
	}
	return out
}

// Mirrors p256.CompressPubkey, (0x02 + parity(y)) || x.
func compress(t testing.TB, publicKey []byte) [33]byte {
	t.Helper()
	key := Uncompressed(t, publicKey)
	var out [33]byte
	out[0] = 2 + (key[64] & 1)
	copy(out[1:], key[1:33])
	return out
}

// Mirrors base.Pack32To2FECircuit.
func pack32(bytes [32]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetUint64(uint64(bytes[31]))
}

// Mirrors base.Pack33To2FECircuit.
func pack33(key [33]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(key[:31]), new(big.Int).SetUint64(uint64(key[31])<<8 | uint64(key[32]))
}

// Mirrors ve.KeySchedule with auditEncInfo as the info string.
func keySchedule(t testing.TB, sharedSecret *big.Int) (key [32]byte, nonce [12]byte) {
	t.Helper()
	siloed := spptest.MustPoseidon(t, 4, []*big.Int{
		tag(ve.DomSepSilo),
		sharedSecret,
		new(big.Int).SetBytes([]byte(auditEncInfo)),
	})
	keyLo := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tag(ve.DomSepKey), siloed}))
	keyHi := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tag(ve.DomSepKey + 1), siloed}))
	nonceRaw := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tag(ve.DomSepNonce), siloed}))

	copy(key[:16], keyHi[16:])
	copy(key[16:], keyLo[16:])
	copy(nonce[:], nonceRaw[20:])
	return key, nonce
}

// Mirrors aes.CTREncrypt, the first keystream block counts from nonce || 2.
func ctrEncrypt(t testing.TB, key [32]byte, nonce [12]byte, plaintext []byte) []byte {
	t.Helper()
	block, err := stdaes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	var counter [16]byte
	copy(counter[:12], nonce[:])
	counter[15] = 2

	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, counter[:]).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func tag(value uint32) *big.Int {
	return new(big.Int).SetUint64(uint64(value))
}

func setBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = int(b)
	}
}
