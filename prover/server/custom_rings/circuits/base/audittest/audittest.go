package audittest

import (
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	ve "zolana/prover/circuits/verifiable-encryption"
	base "zolana/prover/custom_rings/circuits/base"
	"zolana/prover/prover-test/hosttest"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

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

func (k Keys) Seal(t testing.TB, plaintext []byte, info string) Sealed {
	t.Helper()
	dhLo, dhHi := hosttest.PackShared(k.dh)
	ephLo, ephHi := hosttest.PackCompressed(k.ephPk)
	auditorLo, auditorHi := hosttest.PackCompressed(compress(t, k.auditorPk[:]))

	sharedSecret := spptest.MustPoseidon(t, 8, []*big.Int{
		ve.SecretTagValue(base.SharedSecretTag),
		dhLo, dhHi,
		ephLo, ephHi,
		auditorLo, auditorHi,
	})
	key, nonce := hosttest.KeySchedule(sharedSecret, []byte(info))
	ciphertext, err := protocol.HashBytes(hosttest.CTR(key, nonce, plaintext))
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

func (k Keys) ChainElementsFor(t testing.TB, w base.AuditBlockWires, count int) []*big.Int {
	t.Helper()
	txLo, txHi := hosttest.PackCompressed(k.txPk)
	sealed := k.Seal(t, k.txSk[:], base.AuditEncInfo)
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
	keyLo, keyHi := hosttest.PackShared(k.txSk)
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

func compress(t testing.TB, publicKey []byte) [33]byte {
	t.Helper()
	key := Uncompressed(t, publicKey)
	return hosttest.CompressP256(key[:])
}

func setBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = int(b)
	}
}
