package squadskeyencryption_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"math/big"
	"testing"

	. "circuits/key_encryption"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
)

func TestKeyEncryptionWitness(t *testing.T) {
	for _, count := range []int{1, 2, 3} {
		a := keyWitness(t, count, nil)
		if err := test.IsSolved(NewKeyEncryptionCircuit(count), a, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("%d recipients: %v", count, err)
		}
	}
}

// A recovery key may equal the shared viewing key. Distinct KDF contexts must
// still make the viewing-secret and nullifier envelopes use separate streams.
func TestKeyEncryptionSharedViewingRecipient(t *testing.T) {
	a := keyWitness(t, 1, func(pk *[33]byte) {
		raw := [32]byte{}
		for i := range raw {
			raw[i] = 7
		}
		sk, err := ecdh.X25519().NewPrivateKey(raw[:])
		if err != nil {
			t.Fatal(err)
		}
		copy(pk[1:], sk.PublicKey().Bytes())
	})
	if err := test.IsSolved(NewKeyEncryptionCircuit(1), a, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func TestKeyEncryptionRejectsChangedSecrets(t *testing.T) {
	for _, field := range []string{"viewing", "ephemeral", "nullifier", "public_hash"} {
		t.Run(field, func(t *testing.T) {
			a := keyWitness(t, 1, nil)
			switch field {
			// RFC 7748 ignores these low bits during multiplication, but the viewing
			// commitment and ciphertext must bind the complete raw secret anyway.
			case "viewing":
				a.ViewingSecretKey[0] = byte(6)
			case "ephemeral":
				a.EphemeralSecretKey[1] = byte(10)
			case "nullifier":
				a.NullifierSecret = 24
			case "public_hash":
				a.PublicInputHash = 0
			}
			if err := test.IsSolved(NewKeyEncryptionCircuit(1), a, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("changed witness solved")
			}
		})
	}
}

func TestKeyEncryptionRejectsInvalidRecipient(t *testing.T) {
	for _, kind := range []string{"tag", "high_bit", "low_order"} {
		t.Run(kind, func(t *testing.T) {
			// Recompute the public transcript for the malformed wire key, so rejection
			// must come from key constraints rather than a stale public-input hash.
			a := keyWitness(t, 1, func(pk *[33]byte) {
				switch kind {
				case "tag":
					pk[0] = 3
				case "high_bit":
					pk[32] |= 128
				case "low_order":
					for i := 1; i < len(pk); i++ {
						pk[i] = 0
					}
				}
			})
			if err := test.IsSolved(NewKeyEncryptionCircuit(1), a, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("malformed recipient solved")
			}
		})
	}
}

func keyWitness(t *testing.T, count int, mutate func(*[33]byte)) *Circuit {
	t.Helper()
	hash := func(values ...*big.Int) *big.Int {
		out, err := poseidon.Hash(values)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	pack := func(data []byte, chunk int) []*big.Int {
		var out []*big.Int
		for i := 0; i < len(data); i += chunk {
			out = append(out, new(big.Int).SetBytes(data[i:min(i+chunk, len(data))]))
		}
		return out
	}
	chain := func(values []*big.Int) *big.Int {
		acc := values[0]
		for _, v := range values[1:] {
			acc = hash(acc, v)
		}
		return acc
	}
	key := func(b byte) *ecdh.PrivateKey {
		raw := make([]byte, 32)
		for i := range raw {
			raw[i] = b
		}
		sk, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		return sk
	}
	tagged := func(sk *ecdh.PrivateKey) [33]byte {
		var pk [33]byte
		pk[0] = 4
		copy(pk[1:], sk.PublicKey().Bytes())
		return pk
	}
	view, eph := key(7), key(9)
	viewPk, ephPk := tagged(view), tagged(eph)
	encryptHash := func(recipient [33]byte, plaintext []byte, info string) *big.Int {
		pk, err := ecdh.X25519().NewPublicKey(recipient[1:])
		if err != nil {
			t.Fatal(err)
		}
		dh, err := eph.ECDH(pk)
		// Include low-order peers' zero DH in the host transcript. The circuit must
		// reject independently instead of accidentally passing through host checks.
		if err != nil {
			dh = make([]byte, 32)
		}
		inputs := []*big.Int{big.NewInt(0x43545f53)}
		inputs = append(inputs, pack(dh, 31)...)
		inputs = append(inputs, pack(ephPk[:], 31)...)
		inputs = append(inputs, pack(recipient[:], 31)...)
		shared := hash(inputs...)
		siloInputs := []*big.Int{big.NewInt(0x544d5349), shared}
		siloInputs = append(siloInputs, pack([]byte(info), 31)...)
		silo := hash(siloInputs...)
		lo, hi := hash(big.NewInt(0x544d534b), silo), hash(big.NewInt(0x544d534c), silo)
		var loBytes, hiBytes, nonceBytes [32]byte
		lo.FillBytes(loBytes[:])
		hi.FillBytes(hiBytes[:])
		hash(big.NewInt(0x544d534e), silo).FillBytes(nonceBytes[:])
		var aesKey [32]byte
		copy(aesKey[:16], hiBytes[16:])
		copy(aesKey[16:], loBytes[16:])
		var iv [16]byte
		copy(iv[:12], nonceBytes[20:])
		iv[15] = 2
		block, err := aes.NewCipher(aesKey[:])
		if err != nil {
			t.Fatal(err)
		}
		ct := make([]byte, len(plaintext))
		cipher.NewCTR(block, iv[:]).XORKeyStream(ct, plaintext)
		return chain(pack(ct, 31))
	}
	a := NewKeyEncryptionCircuit(count)
	a.OldStateHash = 0
	a.NullifierSecret = 23
	for i := range view.Bytes() {
		a.ViewingSecretKey[i] = view.Bytes()[i]
		a.EphemeralSecretKey[i] = eph.Bytes()[i]
	}
	viewingLimbs := pack(view.Bytes(), 16)
	public := []*big.Int{big.NewInt(0)}
	public = append(public, pack(viewPk[:], 31)...)
	public = append(public, hash(viewingLimbs[1], viewingLimbs[0]))
	public = append(public, pack(ephPk[:], 31)...)
	for i := 0; i < count; i++ {
		recipient := tagged(key(byte(i + 11)))
		if mutate != nil {
			mutate(&recipient)
		}
		for j, b := range recipient {
			a.RecipientKeys[i].Pubkey[j] = b
		}
		public = append(public, pack(recipient[:], 31)...)
		public = append(public, encryptHash(recipient, view.Bytes(), "TSPP/squads/key"))
	}
	nullPlain := make([]byte, 31)
	nullPlain[30] = 23
	public = append(public, hash(big.NewInt(23)), encryptHash(viewPk, nullPlain, "TSPP/squads/nullifier"))
	a.PublicInputHash = chain(public)
	return a
}
