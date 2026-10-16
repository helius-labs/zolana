// Package ringaudit recomputes the audit block of package base on the host.
package ringaudit

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	ve "github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption"
	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Mirrors the unexported key-schedule info string of package base.
const auditEncInfo = "CRING/adt1"

type Keys struct {
	txSk      [32]byte
	ephSk     [32]byte
	txPk      [33]byte
	ephPk     [33]byte
	auditorPk [32]byte
	dh        [32]byte
}

func DefaultKeys(t testing.TB) Keys {
	t.Helper()
	txSk := Clamped(Scalar(0x11))
	ephSk := Scalar(0x22)
	txPriv := XPrivateKey(t, txSk)
	ephPriv := XPrivateKey(t, ephSk)
	auditorPriv := XPrivateKey(t, Scalar(0x33))

	dh, err := ephPriv.ECDH(auditorPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return Keys{
		txSk:      txSk,
		ephSk:     ephSk,
		txPk:      Tagged(txPriv.PublicKey().Bytes()),
		ephPk:     Tagged(ephPriv.PublicKey().Bytes()),
		auditorPk: [32]byte(auditorPriv.PublicKey().Bytes()),
		dh:        [32]byte(dh),
	}
}

// WithTxScalar witnesses the clamped encoding of secret and publishes its key.
func (k Keys) WithTxScalar(t testing.TB, secret [32]byte) Keys {
	t.Helper()
	k.txSk = Clamped(secret)
	k.txPk = Tagged(XPrivateKey(t, k.txSk).PublicKey().Bytes())
	return k
}

// WithRawTxScalar witnesses secret unclamped under the key its clamping publishes.
func (k Keys) WithRawTxScalar(t testing.TB, secret [32]byte) Keys {
	k = k.WithTxScalar(t, secret)
	k.txSk = secret
	return k
}

// WithLegacyTxTag publishes the viewing key under a SEC1 P-256 tag.
func (k Keys) WithLegacyTxTag() Keys {
	k.txPk[0] = 2
	return k
}

// WithLegacyEphTag seals the envelope under a SEC1 P-256 tag.
func (k Keys) WithLegacyEphTag() Keys {
	k.ephPk[0] = 2
	return k
}

// WithEphScalar computes an honest envelope, including RFC 7748 clamping.
func (k Keys) WithEphScalar(t testing.TB, scalar [32]byte) Keys {
	t.Helper()
	key := XPrivateKey(t, scalar)
	peer, err := ecdh.X25519().NewPublicKey(k.auditorPk[:])
	if err != nil {
		t.Fatal(err)
	}
	dh, err := key.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	k.ephSk, k.ephPk, k.dh = scalar, Tagged(key.PublicKey().Bytes()), [32]byte(dh)
	return k
}

func (k Keys) TxSk() [32]byte {
	return k.txSk
}

func (k Keys) EphSk() [32]byte {
	return k.ephSk
}

func (k Keys) AuditorPk() [32]byte {
	return k.auditorPk
}

type Sealed struct {
	AuditorLo      *big.Int
	AuditorHi      *big.Int
	EphLo          *big.Int
	EphHi          *big.Int
	CiphertextHash *big.Int
}

// Mirrors base.Envelope.Seal.
func (k Keys) Seal(t testing.TB, plaintext []byte, info string) Sealed {
	t.Helper()
	dhLo, dhHi := pack32(k.dh)
	ephLo, ephHi := pack33(k.ephPk)
	auditorLo, auditorHi := pack33(Tagged(k.auditorPk[:]))

	sharedSecret := spptest.MustPoseidon(t, 8, []*big.Int{
		tag(base.DomSepCRShared),
		dhLo, dhHi,
		ephLo, ephHi,
		auditorLo, auditorHi,
	})
	key, nonce := keySchedule(t, sharedSecret, info)
	ciphertext, err := protocol.HashBytes(ctrEncrypt(t, key, nonce, plaintext))
	return Sealed{
		AuditorLo:      auditorLo,
		AuditorHi:      auditorHi,
		EphLo:          ephLo,
		EphHi:          ephHi,
		CiphertextHash: spptest.MustHash(t, ciphertext, err),
	}
}

// Statement is the audit witness with the outputs it discloses.
type Statement struct {
	Audit   base.Audit
	Outputs [base.AuditOutputSlots]base.AuditOutputWires
	Count   int
}

// Statement discloses one zero output.
func (k Keys) Statement(privateTxHash *big.Int) Statement {
	s := Statement{Audit: base.Audit{PrivateTxHash: privateTxHash}, Count: 1}
	setBytes(s.Audit.TxViewingSk[:], k.txSk[:])
	setBytes(s.Audit.EphSk[:], k.ephSk[:])
	setBytes(s.Audit.AuditorPk[:], k.auditorPk[:])
	setBytes(s.Audit.Salt[:], make([]byte, 16))
	for i := range s.Outputs {
		s.Outputs[i] = base.AuditOutputWires{
			Domain: big.NewInt(0), TreeID: big.NewInt(0), OwnerHash: big.NewInt(0),
			Asset: big.NewInt(0), Amount: big.NewInt(0), Blinding: big.NewInt(0),
			DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
		}
	}
	return s
}

// ChainElements returns the base chain of a one-slot zero-output statement.
func (k Keys) ChainElements(t testing.TB, privateTxHash *big.Int) []*big.Int {
	return k.ChainElementsFor(t, k.Statement(privateTxHash))
}

func (k Keys) ChainElementsFor(t testing.TB, s Statement) []*big.Int {
	t.Helper()
	txLo, txHi := pack33(k.txPk)
	sealed := k.Seal(t, k.txSk[:], auditEncInfo)
	outputHashes := make([]*big.Int, s.Count)
	plaintext := make([]*big.Int, 0, base.AuditOutputSlots*base.AuditOutputFieldCount)
	for i, output := range s.Outputs {
		fields := spptest.ToBigInts([]frontend.Variable{output.Domain, output.TreeID, output.OwnerHash, output.Asset, output.Amount,
			output.Blinding, output.DataHash, output.RingDataHash, output.RingProgramID})
		if i >= s.Count {
			plaintext = append(plaintext, spptest.RepeatBigInt(big.NewInt(0), base.AuditOutputFieldCount)...)
			continue
		}
		outputHashes[i] = spptest.MustUtxoHash(t, protocol.Utxo{
			Domain: fields[0], Owner: fields[2], Asset: fields[3], Amount: fields[4], Blinding: fields[5],
			DataHash: fields[6], RingDataHash: fields[7], RingProgramID: fields[8],
		}, fields[1])
		plaintext = append(plaintext, fields...)
	}
	keyLo, keyHi := pack32(k.txSk)
	salt := make([]byte, len(s.Audit.Salt))
	for i, value := range s.Audit.Salt {
		salt[i] = byte(spptest.AsBigInt(value).Uint64())
	}
	ciphertext := make([]*big.Int, len(plaintext))
	for i, value := range plaintext {
		stream := spptest.MustPoseidon(t, 6, []*big.Int{
			new(big.Int).SetUint64(0x4352_5f4f44), keyLo, keyHi,
			new(big.Int).SetBytes(salt), big.NewInt(int64(i)),
		})
		ciphertext[i] = new(big.Int).Add(value, stream)
		ciphertext[i].Mod(ciphertext[i], ecc.BN254.ScalarField())
	}
	return []*big.Int{
		spptest.AsBigInt(s.Audit.PrivateTxHash),
		txLo, txHi,
		sealed.AuditorLo, sealed.AuditorHi,
		sealed.EphLo, sealed.EphHi,
		sealed.CiphertextHash,
		spptest.MustHashChain4(t, outputHashes),
		new(big.Int).SetBytes(salt),
		spptest.MustHashChain(t, ciphertext),
	}
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

// Mirrors gadget.PackBytesBE over 32 bytes.
func pack32(bytes [32]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetUint64(uint64(bytes[31]))
}

// Mirrors gadget.PackBytesBE over 33 bytes.
func pack33(key [33]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(key[:31]), new(big.Int).SetUint64(uint64(key[31])<<8 | uint64(key[32]))
}

// Mirrors ve.KeySchedule.
func keySchedule(t testing.TB, sharedSecret *big.Int, info string) (key [32]byte, nonce [12]byte) {
	t.Helper()
	siloed := spptest.MustPoseidon(t, 4, []*big.Int{
		tag(ve.DomSepSilo),
		sharedSecret,
		new(big.Int).SetBytes([]byte(info)),
	})
	keyLo := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tag(ve.DomSepKey), siloed}))
	keyHi := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tag(ve.DomSepKey + 1), siloed}))
	nonceRaw := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tag(ve.DomSepNonce), siloed}))

	copy(key[:16], keyHi[16:])
	copy(key[16:], keyLo[16:])
	copy(nonce[:], nonceRaw[20:])
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

func tag(value uint32) *big.Int {
	return new(big.Int).SetUint64(uint64(value))
}

func setBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = int(b)
	}
}

func XPrivateKey(t testing.TB, scalar [32]byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func Tagged(key []byte) [33]byte { var out [33]byte; out[0] = 4; copy(out[1:], key); return out }
