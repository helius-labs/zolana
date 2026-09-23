package spptest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/big"
	"testing"

	"golang.org/x/crypto/hkdf"
	"zolana/prover/prover-test/spp/protocol"
)

type CounterDisclosure struct {
	Secret          [32]byte
	TransactionSalt [16]byte
	CounterSalt     *big.Int
	Assets          []*big.Int
	Spent           []uint64
}

func (d CounterDisclosure) Body(t *testing.T) []byte {
	t.Helper()
	secret, err := ecdh.P256().NewPrivateKey(d.Secret[:])
	if err != nil {
		t.Fatal(err)
	}
	public := secret.PublicKey()
	x, y := elliptic.Unmarshal(elliptic.P256(), public.Bytes())
	compressed := elliptic.MarshalCompressed(elliptic.P256(), x, y)
	dh, err := secret.ECDH(public)
	if err != nil {
		t.Fatal(err)
	}
	ikm := append(append(dh, compressed...), compressed...)
	info := append([]byte("TSPP/hpke/TSPP/tx"), d.TransactionSalt[:]...)
	info = append(info, 255, 255, 255, 255)
	key := make([]byte, 44)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, info), key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	copy(iv, key[32:])
	iv[15] = 2
	plaintext := make([]byte, 352)
	d.CounterSalt.FillBytes(plaintext[:32])
	for i, asset := range d.Assets {
		asset.FillBytes(plaintext[32+i*40 : 64+i*40])
	}
	for i, spent := range d.Spent {
		binary.LittleEndian.PutUint64(plaintext[64+i*40:72+i*40], spent)
	}
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, plaintext)
	return append(compressed, plaintext...)
}

func (d CounterDisclosure) Hash(t *testing.T) *big.Int {
	t.Helper()
	bytes := append([]byte("CRING/spend-counters/v1"), d.TransactionSalt[:]...)
	bytes = append(bytes, d.Body(t)...)
	hash, err := protocol.HashBytes(bytes)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
