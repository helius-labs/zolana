// Package audittest recomputes the audit block of package base on the host.
package audittest

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	ve "zolana/prover/circuits/verifiable-encryption"
	base "zolana/prover/custom_rings/circuits/base"
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

func (k Keys) EphSk() [32]byte {
	return k.ephSk
}

func (k Keys) AuditorPk() [65]byte {
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
	auditorLo, auditorHi := pack33(compress(t, k.auditorPk[:]))

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

func (k Keys) AuditBlockWires(privateTxHash *big.Int) base.AuditBlockWires {
	w := base.AuditBlockWires{PrivateTxHash: privateTxHash}
	setBytes(w.TxViewingSk[:], k.txSk[:])
	setBytes(w.EphSk[:], k.ephSk[:])
	setBytes(w.AuditorPk[:], k.auditorPk[:])
	for i := range w.Salt {
		w.Salt[i] = 0
	}
	for i := range w.Outputs {
		w.Outputs[i] = zeroOutput()
		w.OutputCountSelected[i] = 0
	}
	w.OutputCountSelected[0] = 1
	return w
}

// ChainElements returns a one-slot zero-output audit statement.
func (k Keys) ChainElements(t testing.TB, privateTxHash *big.Int) []*big.Int {
	w := k.AuditBlockWires(privateTxHash)
	return k.ChainElementsFor(t, w, 1)
}

func (k Keys) ChainElementsFor(t testing.TB, w base.AuditBlockWires, count int) []*big.Int {
	t.Helper()
	txLo, txHi := pack33(k.txPk)
	sealed := k.Seal(t, k.txSk[:], auditEncInfo)
	outputHashes := make([]*big.Int, count)
	plaintext := make([]*big.Int, 0, base.AuditOutputSlots*base.AuditOutputFieldCount)
	for i, output := range w.Outputs {
		fields := outputFields(output)
		if i < count {
			outputHashes[i] = spptest.MustUtxoHash(t, protocol.Utxo{
				Domain: fields[0], Owner: fields[2], Asset: fields[3], Amount: fields[4],
				Blinding: fields[5], DataHash: fields[6], RingDataHash: fields[7],
				RingProgramID: fields[8],
			}, fields[1])
			plaintext = append(plaintext, fields...)
		} else {
			plaintext = append(plaintext, spptest.RepeatBigInt(big.NewInt(0), base.AuditOutputFieldCount)...)
		}
	}
	outputHashChain := spptest.MustHashChain4(t, outputHashes)
	keyLo, keyHi := pack32(k.txSk)
	salt := make([]byte, len(w.Salt))
	for i, value := range w.Salt {
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
		spptest.AsBigInt(w.PrivateTxHash),
		txLo, txHi,
		sealed.AuditorLo, sealed.AuditorHi,
		sealed.EphLo, sealed.EphHi,
		sealed.CiphertextHash,
		outputHashChain,
		new(big.Int).SetBytes(salt),
		spptest.MustHashChain(t, ciphertext),
	}
}

func zeroOutput() base.AuditOutputWires {
	return base.AuditOutputWires{
		Domain: big.NewInt(0), TreeID: big.NewInt(0), OwnerHash: big.NewInt(0),
		Asset: big.NewInt(0), Amount: big.NewInt(0), Blinding: big.NewInt(0),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
	}
}

func outputFields(output base.AuditOutputWires) []*big.Int {
	return []*big.Int{
		spptest.AsBigInt(output.Domain), spptest.AsBigInt(output.TreeID),
		spptest.AsBigInt(output.OwnerHash), spptest.AsBigInt(output.Asset),
		spptest.AsBigInt(output.Amount), spptest.AsBigInt(output.Blinding),
		spptest.AsBigInt(output.DataHash), spptest.AsBigInt(output.RingDataHash),
		spptest.AsBigInt(output.RingProgramID),
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
