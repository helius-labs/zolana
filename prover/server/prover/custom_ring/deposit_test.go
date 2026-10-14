package custom_ring

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	ve "github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/deposit"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Rust and TypeScript tests share the same disclosure statement.
type depositVector struct {
	Params           *DepositParams `json:"params"`
	AuditorPk        string         `json:"auditorPk"`
	EphPk            string         `json:"ephPk"`
	Ciphertexts      []string       `json:"ciphertexts"`
	OwnerCommitments []string       `json:"ownerCommitments"`
	Proof            *common.Proof  `json:"proof,omitempty"`
}

func depositFixture(t *testing.T, count uint32) (depositVector, []*big.Int) {
	t.Helper()
	return encryptDepositVector(t, depositParams(t, count))
}

func encryptDepositVector(t *testing.T, p *DepositParams) (depositVector, []*big.Int) {
	t.Helper()
	owners := make([]*big.Int, deposit.MaxDeposits)
	for i := range owners {
		owners[i] = big.NewInt(0)
		if i < int(p.Count) {
			owners[i] = spptest.MustOwnerHash(t, p.OwnerPkHashes[i].Int, p.NullifierPks[i].Int)
		}
	}
	return sealDeposits(t, p, owners)
}

// Standard AES keeps the host ciphertext independent of the circuit, it seals the owner hashes as given.
func sealDeposits(t *testing.T, p *DepositParams, owners []*big.Int) (depositVector, []*big.Int) {
	t.Helper()
	auditor, err := ecdh.P256().NewPublicKey(p.AuditorPk)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.P256().NewPrivateKey(p.EphSk)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := ephemeral.ECDH(auditor)
	if err != nil {
		t.Fatal(err)
	}
	compress := func(raw []byte) []byte { return append([]byte{2 + raw[64]&1}, raw[1:33]...) }
	ephemeralPk, auditorPk := compress(ephemeral.PublicKey().Bytes()), compress(auditor.Bytes())
	ephLo, ephHi := new(big.Int).SetBytes(ephemeralPk[:31]), new(big.Int).SetBytes(ephemeralPk[31:])
	auditorLo, auditorHi := new(big.Int).SetBytes(auditorPk[:31]), new(big.Int).SetBytes(auditorPk[31:])
	secret := spptest.MustPoseidon(t, 8, []*big.Int{
		new(big.Int).SetUint64(uint64(base.DomSepCRShared)), new(big.Int).SetBytes(dh[:31]), new(big.Int).SetBytes(dh[31:]),
		ephLo, ephHi, auditorLo, auditorHi,
	})
	silo := spptest.MustPoseidon(t, 4, []*big.Int{new(big.Int).SetUint64(uint64(ve.DomSepSilo)), secret, new(big.Int).SetBytes([]byte(deposit.EncryptionInfo))})
	kdf := func(domain uint32) [32]byte {
		return spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{new(big.Int).SetUint64(uint64(domain)), silo}))
	}
	lo, hi, nonce := kdf(ve.DomSepKey), kdf(ve.DomSepKey+1), kdf(ve.DomSepNonce)
	block, err := stdaes.NewCipher(append(append([]byte{}, hi[16:]...), lo[16:]...))
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	copy(iv, nonce[20:])
	iv[15] = 2
	plaintext := make([]byte, deposit.MaxDeposits*deposit.OpeningBytes)
	for i := range owners {
		owners[i].FillBytes(plaintext[i*64 : i*64+32])
		p.Blindings[i].FillBytes(plaintext[i*64+32 : (i+1)*64])
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)
	vector := depositVector{Params: p, AuditorPk: hex.EncodeToString(auditorPk), EphPk: hex.EncodeToString(ephemeralPk)}
	chain := []*big.Int{new(big.Int).SetUint64(uint64(deposit.Domain)), p.ContextHash.Int, new(big.Int).SetUint64(uint64(p.Count))}
	for i := range owners {
		if i >= int(p.Count) {
			chain = append(chain, big.NewInt(0), big.NewInt(0))
			continue
		}
		owner := spptest.MustPoseidon(t, 3, []*big.Int{owners[i], p.Blindings[i].Int})
		ct := ciphertext[i*64 : (i+1)*64]
		hash, err := protocol.HashBytes(ct)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, owner, hash)
		vector.Ciphertexts = append(vector.Ciphertexts, hex.EncodeToString(ct))
		vector.OwnerCommitments = append(vector.OwnerCommitments, common.ToHex(owner))
	}
	keyEscrow := big.NewInt(0)
	if p.KeyEscrow {
		keyEscrow.SetInt64(1)
	}
	chain = append(chain, auditorLo, auditorHi, ephLo, ephHi, keyEscrow, p.KeyRegistryRoot.Int)
	p.PublicInputHash = fb(spptest.MustHashChain(t, chain))
	return vector, chain
}

func TestDepositMatchesSharedHostVector(t *testing.T) {
	p := &DepositParams{Count: 2, EphSk: make(Bytes, 32), KeyRegistryRoot: fi(0), Blindings: zeros(deposit.MaxDeposits)}
	auditorSk := make([]byte, 32)
	for i := range auditorSk {
		auditorSk[i], p.EphSk[i] = 0x11, 0x22
	}
	auditor, err := ecdh.P256().NewPrivateKey(auditorSk)
	if err != nil {
		t.Fatal(err)
	}
	p.AuditorPk = auditor.PublicKey().Bytes()
	if err := json.Unmarshal([]byte(`"0x2cc6b9a5a2cb550702b5387ade744abee5e6eeb7c266415e59502e6f8acce56b"`), &p.ContextHash); err != nil {
		t.Fatal(err)
	}
	owners := make([]*big.Int, deposit.MaxDeposits)
	for i := range owners {
		owners[i] = big.NewInt(0)
		if i < 2 {
			owners[i], p.Blindings[i] = big.NewInt(int64(i+1)), fi(int64(i+3))
		}
	}
	vector, _ := sealDeposits(t, p, owners)
	want := []string{
		"146b393f9c81cad9bc22887e500644f69ea8293e2253f55869e88127e5483e9b12a46abadf0068bd73c83584a8e47a550e88a35558642ba87646ff0765c5e3b5",
		"74e42b590ba76cfee5c6d8e3e05e03a460e0c02c7330fd977dc4eb71e34645616f616fb39595f1ecadfdd87feffd48fb4177741341dd2d507c474094e252f89c",
	}
	for i := range want {
		if vector.Ciphertexts[i] != want[i] {
			t.Fatalf("ciphertext %d differs from the Rust/TypeScript vector", i)
		}
	}
	if common.ToHex(p.PublicInputHash.Int) != "0x0bc3f76e72b6d6bd1a557447da49e445dafb11e6d9168005742013130b45e030" {
		t.Fatalf("public hash %s differs from the Rust/TypeScript vector", common.ToHex(p.PublicInputHash.Int))
	}
}

func solveDeposit(t *testing.T, p *DepositParams) error {
	t.Helper()
	cs := compileRing(t, common.CustomRingDepositCircuitType)
	witness, err := frontend.NewWitness(decodeParams(t, common.CustomRingDepositCircuitType, p), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	_, err = cs.Solve(witness)
	return err
}

func TestDepositCircuitBindsEveryOpeningAndCiphertext(t *testing.T) {
	for _, count := range []uint32{1, 2, 8} {
		vector, _ := depositFixture(t, count)
		if err := solveDeposit(t, vector.Params); err != nil {
			t.Fatalf("count %d: %v", count, err)
		}
	}
	for _, name := range []string{"owner", "nullifier key", "blinding", "context", "count", "padding", "auditor", "ephemeral", "ciphertext", "order", "key escrow", "empty batch", "oversized batch"} {
		t.Run(name, func(t *testing.T) {
			vector, chain := depositFixture(t, 2)
			p := vector.Params
			rebind := func() { p.PublicInputHash = fb(spptest.MustHashChain(t, chain)) }
			switch name {
			case "owner":
				p.OwnerPkHashes[0] = fi(99)
			case "nullifier key":
				p.NullifierPks[0] = fi(99)
			case "blinding":
				p.Blindings[0] = fi(99)
			case "context":
				p.ContextHash = fi(99)
			case "count":
				p.Count = 1
			case "padding":
				p.NullifierPks[7] = fi(99)
			case "auditor":
				p.AuditorPk = auditorKey(t, 0x44)
			case "ephemeral":
				p.EphSk = testScalar(0x44)
			case "ciphertext":
				chain[4] = big.NewInt(99)
				rebind()
			case "order":
				chain[3], chain[5] = chain[5], chain[3]
				chain[4], chain[6] = chain[6], chain[4]
				rebind()
			case "key escrow":
				chain[len(chain)-2] = big.NewInt(1)
				rebind()
			case "empty batch", "oversized batch":
				// Zero padding isolates the count range check.
				p.Count = 0
				p.OwnerPkHashes, p.NullifierPks, p.Blindings = zeros(deposit.MaxDeposits), zeros(deposit.MaxDeposits), zeros(deposit.MaxDeposits)
				_, chain = encryptDepositVector(t, p)
				chain[2] = big.NewInt(0)
				if name == "oversized batch" {
					p.Count, chain[2] = deposit.MaxDeposits+1, big.NewInt(deposit.MaxDeposits+1)
				}
				rebind()
			}
			if solveDeposit(t, p) == nil {
				t.Fatal("tampered deposit solved")
			}
		})
	}
}

func TestDepositKeysMustBeEscrowed(t *testing.T) {
	tests := []struct {
		name   string
		change func(*DepositParams)
		passes bool
	}{
		{"registered keys", func(p *DepositParams) { escrowDeposits(t, p) }, true},
		{"zero key without a registration", func(p *DepositParams) {
			escrowDeposits(t, p)
			p.NullifierPks[1], p.Keys[1] = fb(registry.ZeroNullifierPk), nil
		}, false},
		{"unregistered keys with escrow off", func(*DepositParams) {}, true},
		{"unregistered key", func(p *DepositParams) {
			escrowDeposits(t, p)
			p.Keys[1] = nil
		}, false},
		{"registry root with escrow off", func(p *DepositParams) {
			escrowDeposits(t, p)
			p.KeyEscrow = false
		}, false},
		{"another slot's leaf", func(p *DepositParams) {
			escrowDeposits(t, p)
			p.Keys[1] = p.Keys[0]
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := depositParams(t, 2)
			tt.change(p)
			encryptDepositVector(t, p)
			if err := solveDeposit(t, p); (err == nil) != tt.passes {
				t.Fatalf("passes=%v, solve=%v", tt.passes, err)
			}
		})
	}
}

func TestDepositProofVerifiesEndToEnd(t *testing.T) {
	vector, chain := depositFixture(t, 2)
	if context := os.Getenv("DEPOSIT_CONTEXT_HASH"); context != "" {
		if err := json.Unmarshal([]byte(`"`+context+`"`), &vector.Params.ContextHash); err != nil {
			t.Fatal(err)
		}
		chain[1] = vector.Params.ContextHash.Int
		vector.Params.PublicInputHash = fb(spptest.MustHashChain(t, chain))
	}
	ps := loadRingSystem(t, common.CustomRingDepositCircuitType)
	assignment := decodeParams(t, common.CustomRingDepositCircuitType, vector.Params)
	proof, err := Prove(ps, assignment, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProof(ps, proof, assignment); err != nil {
		t.Fatal(err)
	}
	statement := vector.Params.PublicInputHash
	chain[4] = big.NewInt(99)
	vector.Params.PublicInputHash = fb(spptest.MustHashChain(t, chain))
	if verifyProof(ps, proof, decodeParams(t, common.CustomRingDepositCircuitType, vector.Params)) == nil {
		t.Fatal("proof admitted under a different statement")
	}
	vector.Params.PublicInputHash, vector.Proof = statement, proof
	writeDepositVector(t, vector)
}

// The program fixture supplies the final deposit context.
func TestDepositFixture(t *testing.T) {
	vector, _ := depositFixture(t, 2)
	writeDepositVector(t, vector)
}

func writeDepositVector(t *testing.T, vector depositVector) {
	t.Helper()
	if path := os.Getenv("DEPOSIT_VECTOR_OUT"); path != "" {
		encoded, err := json.MarshalIndent(vector, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
