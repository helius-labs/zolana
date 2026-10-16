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
	Params           *DepositParameters `json:"params"`
	AuditorPk        string             `json:"auditorPk"`
	EphPk            string             `json:"ephPk"`
	Ciphertexts      []string           `json:"ciphertexts"`
	OwnerCommitments []string           `json:"ownerCommitments"`
	Proof            *common.Proof      `json:"proof,omitempty"`
}

// Standard AES keeps the host ciphertext independent of the circuit.
func depositFixture(t *testing.T, count uint32) (depositVector, []*big.Int) {
	t.Helper()
	p := &DepositParameters{ContextHash: big.NewInt(0xabcdef), Count: count, EphSk: testScalar(0x22)}
	auditorSk := testScalar(0x33)
	auditor, err := ecdh.X25519().NewPrivateKey(auditorSk[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(p.AuditorPk[:], auditor.PublicKey().Bytes())
	p.KeyEscrow = KeyEscrow{Root: big.NewInt(0)}
	for i := range p.OwnerPkHashes {
		p.OwnerPkHashes[i], p.NullifierPks[i], p.Blindings[i] = big.NewInt(0), big.NewInt(0), big.NewInt(0)
		if i < int(count) {
			p.OwnerPkHashes[i] = big.NewInt(int64(11 + i))
			p.NullifierPks[i] = spptest.MustNullifierPk(t, big.NewInt(int64(51+i)))
			p.Blindings[i] = big.NewInt(int64(91 + i))
		}
	}
	// Values near the field modulus must retain their full encoding.
	p.Blindings[count-1] = new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
	return encryptDepositVector(t, p)
}

func encryptDepositVector(t *testing.T, p *DepositParameters) (depositVector, []*big.Int) {
	t.Helper()
	owners := make([]*big.Int, deposit.MaxDeposits)
	for i := range owners {
		owners[i] = big.NewInt(0)
		if i < int(p.Count) {
			owners[i] = spptest.MustOwnerHash(t, p.OwnerPkHashes[i], p.NullifierPks[i])
		}
	}
	return sealDeposits(t, p, owners)
}

// Seals the owner hashes as given, the shared vector pins raw values.
func sealDeposits(t *testing.T, p *DepositParameters, owners []*big.Int) (depositVector, []*big.Int) {
	t.Helper()
	auditor, err := ecdh.X25519().NewPublicKey(p.AuditorPk[:])
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.X25519().NewPrivateKey(p.EphSk[:])
	if err != nil {
		t.Fatal(err)
	}
	dh, err := ephemeral.ECDH(auditor)
	if err != nil {
		t.Fatal(err)
	}
	compress := func(raw []byte) []byte { return append([]byte{4}, raw...) }
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
	key := append(append([]byte{}, hi[16:]...), lo[16:]...)
	block, err := stdaes.NewCipher(key)
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
	anonymous := big.NewInt(0)
	if p.Anonymous {
		anonymous.SetInt64(1)
	}
	chain := []*big.Int{new(big.Int).SetUint64(uint64(deposit.Domain)), p.ContextHash, new(big.Int).SetUint64(uint64(p.Count)), anonymous}
	for i := range owners {
		if i < int(p.Count) {
			owner := spptest.MustPoseidon(t, 3, []*big.Int{owners[i], p.Blindings[i]})
			ct := ciphertext[i*64 : (i+1)*64]
			hash, err := protocol.HashBytes(ct)
			if err != nil {
				t.Fatal(err)
			}
			chain = append(chain, owner, hash)
			vector.Ciphertexts = append(vector.Ciphertexts, hex.EncodeToString(ct))
			vector.OwnerCommitments = append(vector.OwnerCommitments, common.ToHex(owner))
		} else {
			chain = append(chain, big.NewInt(0), big.NewInt(0))
		}
	}
	keyEscrow := big.NewInt(0)
	if p.KeyEscrow.Enabled {
		keyEscrow.SetInt64(1)
	}
	chain = append(chain, auditorLo, auditorHi, ephLo, ephHi, keyEscrow, p.KeyEscrow.Root)
	p.PublicInputHash = spptest.MustHashChain(t, chain)
	return vector, chain
}

func TestDepositMatchesSharedHostVector(t *testing.T) {
	p := &DepositParameters{Count: 2}
	var auditorSk [32]byte
	for i := range auditorSk {
		auditorSk[i], p.EphSk[i] = 0x11, 0x22
	}
	auditor, err := ecdh.X25519().NewPrivateKey(auditorSk[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(p.AuditorPk[:], auditor.PublicKey().Bytes())
	p.ContextHash, err = fieldFromHex("0x2cc6b9a5a2cb550702b5387ade744abee5e6eeb7c266415e59502e6f8acce56b", "contextHash")
	if err != nil {
		t.Fatal(err)
	}
	p.KeyEscrow = KeyEscrow{Root: big.NewInt(0)}
	owners := make([]*big.Int, deposit.MaxDeposits)
	for i := range owners {
		owners[i], p.Blindings[i] = big.NewInt(0), big.NewInt(0)
		if i < 2 {
			owners[i], p.Blindings[i] = big.NewInt(int64(i+1)), big.NewInt(int64(i+3))
		}
	}
	vector, _ := sealDeposits(t, p, owners)
	want := []string{
		"006d5d4d188464de0e852c806b11ef3850cd683b977fea9bd1b9278b6461669f631350fa47a91f10cceb37738a4fefe7f88ded2f36b08fa08cb0ebba02684144",
		"24ab3ee9887da5fa32d2074fbd7155bc72723a28dacb3fd92f045649bba3cdf4588ca73e11d9094a68cc5e7c26aadac08f1bc0f41c3580bf9ddc70518b26a820",
	}
	for i := range want {
		if vector.Ciphertexts[i] != want[i] {
			t.Errorf("ciphertext %d: got %s want %s", i, vector.Ciphertexts[i], want[i])
		}
	}
	if common.ToHex(p.PublicInputHash) != "0x082572ed72398c62f6306725b8142c43daa0b5b9f83eb9d12663cdd59057a39a" {
		t.Fatalf("public hash %s differs from the Rust/TypeScript vector", common.ToHex(p.PublicInputHash))
	}
}

func TestDepositCircuitBindsEveryOpeningAndCiphertext(t *testing.T) {
	cs, err := R1CSDeposit()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("deposit constraints=%d public=%d", cs.GetNbConstraints(), cs.GetNbPublicVariables())
	check := func(p *DepositParameters, valid bool) {
		t.Helper()
		assignment, err := p.CreateWitness()
		if err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		_, err = cs.Solve(witness)
		if (err == nil) != valid {
			t.Fatalf("valid=%v, solve=%v", valid, err)
		}
	}
	for _, count := range []uint32{1, 2, 8} {
		vector, _ := depositFixture(t, count)
		check(vector.Params, true)
	}
	anonymousVector, _ := depositFixture(t, 1)
	anonymous := anonymousVector.Params
	anonymous.Anonymous = true
	for i := range anonymous.OwnerKeys[0] {
		anonymous.OwnerKeys[0][i] = byte(i + 1)
	}
	identity := append([]byte{protocol.SolanaOwnerTag}, anonymous.OwnerKeys[0][:]...)
	owner, err := protocol.HashBytes(identity)
	if err != nil {
		t.Fatal(err)
	}
	anonymous.OwnerPkHashes[0] = owner
	encryptDepositVector(t, anonymous)
	check(anonymous, true)
	anonymous.OwnerKeys[0][0] ^= 1
	check(anonymous, false)
	anonymous.OwnerKeys[0][0] ^= 1
	anonymous.Anonymous = false
	check(anonymous, false)
	anonymous.Anonymous = true
	anonymous.OwnerPkHashes[0] = big.NewInt(11)
	encryptDepositVector(t, anonymous)
	check(anonymous, false)
	for _, name := range []string{"owner", "nullifier key", "blinding", "context", "count", "padding", "auditor", "ephemeral", "ciphertext", "order", "key escrow"} {
		t.Run(name, func(t *testing.T) {
			vector, chain := depositFixture(t, 2)
			p := vector.Params
			switch name {
			case "owner":
				p.OwnerPkHashes[0] = big.NewInt(99)
			case "nullifier key":
				p.NullifierPks[0] = big.NewInt(99)
			case "blinding":
				p.Blindings[0] = big.NewInt(99)
			case "context":
				p.ContextHash = big.NewInt(99)
			case "count":
				p.Count = 1
			case "padding":
				p.NullifierPks[7] = big.NewInt(99)
			case "auditor":
				sk := testScalar(0x44)
				key, err := ecdh.X25519().NewPrivateKey(sk[:])
				if err != nil {
					t.Fatal(err)
				}
				copy(p.AuditorPk[:], key.PublicKey().Bytes())
			case "ephemeral":
				p.EphSk = testScalar(0x44)
			case "ciphertext":
				chain[5] = big.NewInt(99)
				p.PublicInputHash = spptest.MustHashChain(t, chain)
			case "order":
				chain[4], chain[6] = chain[6], chain[4]
				chain[5], chain[7] = chain[7], chain[5]
				p.PublicInputHash = spptest.MustHashChain(t, chain)
			case "key escrow":
				chain[len(chain)-2] = big.NewInt(1)
				p.PublicInputHash = spptest.MustHashChain(t, chain)
			}
			check(p, false)
		})
	}
}

func TestDepositParametersRejectAliasesAndMalformedShapes(t *testing.T) {
	vector, _ := depositFixture(t, 2)
	for _, name := range []string{"count", "short", "long", "alias", "padding", "low_order_auditor", "legacy_p256_length", "short_keys", "padding_key", "unescrowed", "zero_key_unescrowed", "root_without_escrow"} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(vector.Params)
			if err != nil {
				t.Fatal(err)
			}
			var raw depositParametersJSON
			if err := json.Unmarshal(encoded, &raw); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "count":
				raw.Count = 9
			case "short":
				raw.NullifierPks = raw.NullifierPks[:7]
			case "long":
				raw.Blindings = append(raw.Blindings, "0x0")
			case "alias":
				raw.OwnerPkHashes[0] = common.ToHex(ecc.BN254.ScalarField())
			case "padding":
				raw.OwnerPkHashes[7] = common.ToHex(big.NewInt(1))
			case "short_keys":
				raw.Keys = raw.Keys[:7]
			case "padding_key":
				raw.Keys[7] = writeRegistryKey(&RegistryKey{Next: big.NewInt(1), CtHash: big.NewInt(1), Path: zeroedKeyPath()})
			case "unescrowed":
				raw.KeyEscrow = true
			case "zero_key_unescrowed":
				raw.KeyEscrow = true
				raw.NullifierPks[0] = common.ToHex(registry.ZeroNullifierPk)
			case "root_without_escrow":
				raw.KeyRegistryRoot = raw.ContextHash
			case "low_order_auditor":
				raw.AuditorPk = "0x" + hex.EncodeToString(make([]byte, 32))
			case "legacy_p256_length":
				raw.AuditorPk = "0x" + hex.EncodeToString(make([]byte, 65))
			}
			encoded, err = json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRequest(common.CustomRingDepositCircuitType, encoded); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestDepositProofVerifiesEndToEnd(t *testing.T) {
	vector, chain := depositFixture(t, 2)
	if context := os.Getenv("DEPOSIT_CONTEXT_HASH"); context != "" {
		value, err := fieldFromHex(context, "contextHash")
		if err != nil {
			t.Fatal(err)
		}
		vector.Params.ContextHash, chain[1] = value, value
		vector.Params.PublicInputHash = spptest.MustHashChain(t, chain)
	}
	ps := loadRingSystem(t, common.CustomRingDepositKeyFile)
	encoded, err := json.Marshal(vector.Params)
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeRequest(common.CustomRingDepositCircuitType, encoded)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := RingProof{System: ps, Parameters: request}.Prove()
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := request.assignment()
	if err != nil {
		t.Fatal(err)
	}
	verifyInstalledProof(t, ps, proof, assignment)
	chain[4] = big.NewInt(99)
	vector.Params.PublicInputHash = spptest.MustHashChain(t, chain)
	tampered, err := vector.Params.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	rejectInstalledProof(t, ps, proof, tampered)
	vector.Params.PublicInputHash = assignment.(*deposit.CustomRingDepositCircuit).PublicInputHash.(*big.Int)
	vector.Proof = proof
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
