// Package ringaudit recomputes the audit statements of package base on the host.
package ringaudit

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	ve "github.com/helius-labs/zolana/prover/server/circuits/encryption"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Mirrors the unexported audit stream schedule tag of package base.
const auditEncInfo = "CRING/adt1"

// Keys are the envelope keys of one audited transfer.
type Keys struct {
	txViewingSk [32]byte
	ephSk       [32]byte
	txPk        [33]byte
	ephPk       [33]byte
	auditorPk   [32]byte
	dh          [32]byte
}

func DefaultKeys(t testing.TB) Keys {
	t.Helper()
	txViewingSk := Clamped(Scalar(0x11))
	ephSk := Scalar(0x22)
	txPriv := XPrivateKey(t, txViewingSk)
	ephPriv := XPrivateKey(t, ephSk)
	auditorPriv := XPrivateKey(t, Scalar(0x33))

	dh, err := ephPriv.ECDH(auditorPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return Keys{
		txViewingSk: txViewingSk,
		ephSk:       ephSk,
		txPk:        Tagged(txPriv.PublicKey().Bytes()),
		ephPk:       Tagged(ephPriv.PublicKey().Bytes()),
		auditorPk:   [32]byte(auditorPriv.PublicKey().Bytes()),
		dh:          [32]byte(dh),
	}
}

// WithRawTxScalar witnesses secret unclamped under the key its clamping publishes.
func (k Keys) WithRawTxScalar(t testing.TB, secret [32]byte) Keys {
	t.Helper()
	k.txPk = Tagged(XPrivateKey(t, Clamped(secret)).PublicKey().Bytes())
	k.txViewingSk = secret
	return k
}

func (k Keys) TxViewingSk() [32]byte {
	return k.txViewingSk
}

func (k Keys) EphSk() [32]byte {
	return k.ephSk
}

func (k Keys) AuditorPk() [32]byte {
	return k.auditorPk
}

func (k Keys) EphPk() [33]byte {
	return k.ephPk
}

type Sealed struct {
	AuditorLo      *big.Int
	AuditorHi      *big.Int
	EphLo          *big.Int
	EphHi          *big.Int
	CiphertextHash *big.Int
}

// Seal mirrors base.Envelope.Seal under the verifiable-encryption schedule of info.
func (k Keys) Seal(t testing.TB, plaintext []byte, info string) Sealed {
	t.Helper()
	return k.sealed(t, k.EnvelopeCiphertext(t, plaintext, info))
}

// SealAuditStream mirrors base.Envelope.SealAuditStream.
func (k Keys) SealAuditStream(t testing.TB, plaintext []byte) Sealed {
	t.Helper()
	return k.sealed(t, k.auditStreamCiphertext(t, plaintext))
}

// AuditHead is the statement head of a transfer sealing the transaction viewing key under the audit stream.
func (k Keys) AuditHead(t testing.TB, firstNullifier, ringID *big.Int, salt [16]byte) AuditHead {
	t.Helper()
	return AuditHead{
		FirstNullifier: firstNullifier,
		RingProgramID:  ringID,
		TxViewingU:     [32]byte(k.txPk[1:]),
		AuditorPubkey:  Tagged(k.auditorPk[:]),
		EphU:           [32]byte(k.ephPk[1:]),
		Sealed:         k.auditStreamCiphertext(t, k.txViewingSk[:]),
		Salt:           salt,
	}
}

func (k Keys) EnvelopeCiphertext(t testing.TB, plaintext []byte, info string) []byte {
	t.Helper()
	key, nonce := infoKeySchedule(t, k.envelopeSecret(t), info)
	return ctrEncrypt(t, key, nonce, plaintext)
}

func (k Keys) auditStreamCiphertext(t testing.TB, plaintext []byte) []byte {
	t.Helper()
	key, nonce := AuditStreamKeys(t, k.envelopeSecret(t))
	return ctrEncrypt(t, key, nonce, plaintext)
}

// Disclose adds the CROD pad of the transaction key and salt to every field.
func (k Keys) Disclose(t testing.TB, salt [16]byte, fields []*big.Int) []*big.Int {
	t.Helper()
	pad := DomainPad(t, base.DisclosurePadDomain, k.txViewingSk, salt, len(fields))
	ciphertext := make([]*big.Int, len(fields))
	for i, field := range fields {
		ciphertext[i] = new(big.Int).Add(field, pad[i])
		ciphertext[i].Mod(ciphertext[i], ecc.BN254.ScalarField())
	}
	return ciphertext
}

// envelopeSecret is Poseidon(CR_S, pack_be(dh), pack_be(eph), pack_be(auditor)) of the envelope.
func (k Keys) envelopeSecret(t testing.TB) *big.Int {
	t.Helper()
	dhLo, dhHi := pack32(k.dh)
	ephLo, ephHi := pack33(k.ephPk)
	auditorLo, auditorHi := pack33(Tagged(k.auditorPk[:]))
	return hash(t, tag(base.DomSepCRShared), dhLo, dhHi, ephLo, ephHi, auditorLo, auditorHi)
}

func (k Keys) sealed(t testing.TB, ciphertext []byte) Sealed {
	t.Helper()
	ephLo, ephHi := pack33(k.ephPk)
	auditorLo, auditorHi := pack33(Tagged(k.auditorPk[:]))
	return Sealed{
		AuditorLo:      auditorLo,
		AuditorHi:      auditorHi,
		EphLo:          ephLo,
		EphHi:          ephHi,
		CiphertextHash: HashBytes(t, ciphertext),
	}
}

// DomainPad mirrors gadget.DisclosurePad under one seed domain.
func DomainPad(t testing.TB, domain uint64, key [32]byte, salt [16]byte, n int) []*big.Int {
	t.Helper()
	keyLo, keyHi := pack32(key)
	seed := hash(t, new(big.Int).SetUint64(domain), keyLo, keyHi, new(big.Int).SetBytes(salt[:]))
	pad := make([]*big.Int, n)
	for i := range pad {
		pad[i] = hash(t, seed, big.NewInt(int64(i)))
	}
	return pad
}

// PackDisclosure mirrors base.PackDisclosure, the short last chunk keeps its bytes first.
func PackDisclosure(bytes []byte) []*big.Int {
	const chunk = 31
	padded := append(append([]byte{}, bytes...), make([]byte, (chunk-len(bytes)%chunk)%chunk)...)
	fields := make([]*big.Int, len(padded)/chunk)
	for i := range fields {
		fields[i] = new(big.Int).SetBytes(padded[i*chunk : (i+1)*chunk])
	}
	return fields
}

// Scalar is byte i = seed ^ i with a 0x01 lead byte, the fixture every cross-language vector derives from.
func Scalar(seed byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	out[0] = 0x01
	return out
}

// Clamped is the RFC 7748 clamping of secret, the one encoding the circuit accepts as plaintext.
func Clamped(secret [32]byte) [32]byte {
	secret[0] &= 248
	secret[31] = (secret[31] & 127) | 64
	return secret
}

// Repeat is 32 copies of one byte.
func Repeat(value byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = value
	}
	return out
}

// HashBytes is protocol.HashBytes with the test failing on a hashing error.
func HashBytes(t testing.TB, bytes []byte) *big.Int {
	t.Helper()
	hash, err := protocol.HashBytes(bytes)
	return spptest.MustHash(t, hash, err)
}

func XPrivateKey(t testing.TB, scalar [32]byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// XPublicKey is the X25519 u of scalar.
func XPublicKey(t testing.TB, scalar [32]byte) [32]byte {
	t.Helper()
	return [32]byte(XPrivateKey(t, scalar).PublicKey().Bytes())
}

// Tagged is the 0x04 || u encoding of an X25519 key.
func Tagged(key []byte) [33]byte {
	var out [33]byte
	out[0] = 4
	copy(out[1:], key)
	return out
}

// Mirrors gadget.PackBytesBE over 32 bytes.
func pack32(bytes [32]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetUint64(uint64(bytes[31]))
}

// Mirrors gadget.PackBytesBE over 33 bytes.
func pack33(key [33]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(key[:31]), new(big.Int).SetUint64(uint64(key[31])<<8 | uint64(key[32]))
}

// Mirrors ve.KeySchedule.
func infoKeySchedule(t testing.TB, sharedSecret *big.Int, info string) (key [32]byte, nonce [12]byte) {
	t.Helper()
	siloed := hash(t, tag(ve.DomSepSilo), sharedSecret, new(big.Int).SetBytes([]byte(info)))
	keyLo := spptest.MustFieldBytes(t, hash(t, tag(ve.DomSepKey), siloed))
	keyHi := spptest.MustFieldBytes(t, hash(t, tag(ve.DomSepKey+1), siloed))
	nonceRaw := spptest.MustFieldBytes(t, hash(t, tag(ve.DomSepNonce), siloed))
	copy(key[:16], keyHi[16:])
	copy(key[16:], keyLo[16:])
	copy(nonce[:], nonceRaw[20:])
	return key, nonce
}

// AuditStreamKeys mirrors the audit stream schedule of package base.
func AuditStreamKeys(t testing.TB, secret *big.Int) (key [32]byte, nonce [12]byte) {
	t.Helper()
	head := spptest.MustFieldBytes(t, hash(t, new(big.Int).SetBytes(append([]byte(auditEncInfo), 0)), secret))
	tail := spptest.MustFieldBytes(t, hash(t, new(big.Int).SetBytes(append([]byte(auditEncInfo), 1)), secret))
	copy(key[:31], head[1:])
	key[31] = tail[19]
	copy(nonce[:], tail[20:])
	return key, nonce
}

// Mirrors aes.Cipher.CTREncrypt, the first keystream block counts from nonce || 2.
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

func hash(t testing.TB, inputs ...*big.Int) *big.Int {
	t.Helper()
	value, err := poseidon.Hash(inputs)
	return spptest.MustHash(t, value, err)
}

func tag(value uint32) *big.Int {
	return new(big.Int).SetUint64(uint64(value))
}

func setBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = int(b)
	}
}
