package policy_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/prover-test/refusal"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// keyEnvelope seals a nullifier secret for member under the default audit keys and binds the statement.
func keyEnvelope(t *testing.T, member *big.Int) (*policy.KeyRegisterCircuit, *big.Int) {
	t.Helper()
	secret := ringaudit.Scalar(0x07)
	secret[0] = 0
	keys := ringaudit.DefaultKeys(t)
	sealed := keys.Seal(t, secret[:], policy.NfKeyEncInfo)
	nullifierPk := spptest.MustNullifierPk(t, new(big.Int).SetBytes(secret[1:]))
	c := &policy.KeyRegisterCircuit{Member: member}
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	for i := range secret {
		c.NullifierSecret[i], c.EphSk[i], c.AuditorPk[i] = int(secret[i]), int(eph[i]), int(auditor[i])
	}
	c.PublicInputHash = keyStatement(t, member, nullifierPk, sealed)
	return c, nullifierPk
}

// keyStatement is the CRRG statement of an honest witness, the honest solve holds it to the circuit's order.
func keyStatement(t *testing.T, member, nullifierPk *big.Int, sealed ringaudit.Sealed) *big.Int {
	t.Helper()
	return spptest.MustHashChain4(t, []*big.Int{
		big.NewInt(base.RegisterKeyDomain), member, nullifierPk,
		sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
	})
}

func TestKeyRegisterSealsTheEscrowedSecret(t *testing.T) {
	c, _ := keyEnvelope(t, big.NewInt(0x0a))
	if err := test.IsSolved(&policy.KeyRegisterCircuit{}, c, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

// keyStatementVector is the register_key case custom-rings/interface/tests/statements.rs writes.
type keyStatementVector struct {
	Member          ringrecords.Hex `json:"member"`
	NullifierPk     ringrecords.Hex `json:"nullifier_pk"`
	AuditorPubkey   string          `json:"auditor_pubkey"`
	EphU            string          `json:"eph_u"`
	Ciphertext      string          `json:"ciphertext"`
	PublicInputHash ringrecords.Hex `json:"public_input_hash"`
}

// keyStatementCircuit feeds the vector's envelope to the circuit's statement as base.Sealed packs it.
type keyStatementCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Member          frontend.Variable
	NullifierPk     frontend.Variable
	AuditorPubkey   [33]frontend.Variable
	EphU            [32]frontend.Variable
	Ciphertext      [32]frontend.Variable
}

func (c *keyStatementCircuit) Define(api frontend.API) error {
	sealed := base.Sealed{
		Auditor:    gadget.PackBytesBE(api, c.AuditorPubkey[:]),
		Eph:        gadget.PackBytesBE(api, append([]frontend.Variable{4}, c.EphU[:]...)),
		Ciphertext: c.Ciphertext[:],
	}
	statement := policy.KeyStatement(api, &policy.KeyRegisterCircuit{Member: c.Member}, c.NullifierPk, sealed)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

// The Rust case is not a sealed envelope, so the circuit's statement method is solved against its public input.
func TestKeyRegisterStatementMatchesRustVector(t *testing.T) {
	raw, err := os.ReadFile(statementVectors)
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		RegisterKey keyStatementVector `json:"register_key"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	v := vectors.RegisterKey
	witness := &keyStatementCircuit{PublicInputHash: v.PublicInputHash.Int, Member: v.Member.Int, NullifierPk: v.NullifierPk.Int}
	for _, field := range []struct {
		value string
		wires []frontend.Variable
	}{{v.AuditorPubkey, witness.AuditorPubkey[:]}, {v.EphU, witness.EphU[:]}, {v.Ciphertext, witness.Ciphertext[:]}} {
		bytes, err := hex.DecodeString(field.value)
		if err != nil || len(bytes) != len(field.wires) {
			t.Fatalf("invalid %d-byte vector value %q", len(field.wires), field.value)
		}
		for i, b := range bytes {
			field.wires[i] = int(b)
		}
	}
	if err := test.IsSolved(&keyStatementCircuit{}, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("the register_key statement differs from the Rust vector: %v", err)
	}
	witness.PublicInputHash = new(big.Int).Add(v.PublicInputHash.Int, big.NewInt(1))
	if test.IsSolved(&keyStatementCircuit{}, witness, ecc.BN254.ScalarField()) == nil {
		t.Fatal("the statement solved under another public input")
	}
}

// Each case changes one value of an honest envelope, the named frames raise the refusal.
func TestKeyRegisterRefusals(t *testing.T) {
	statement := []string{"[assertIsEqual]", "policy.(*KeyRegisterCircuit).Define"}
	tests := []struct {
		name   string
		tamper func(*testing.T, *policy.KeyRegisterCircuit)
		frames []string
	}{
		{"secret with a nonzero lead byte", func(t *testing.T, c *policy.KeyRegisterCircuit) {
			// The statement seals the 32 tampered bytes, the key still derives from the low 31.
			secret := ringaudit.Scalar(0x07)
			secret[0] = 1
			sealed := ringaudit.DefaultKeys(t).Seal(t, secret[:], policy.NfKeyEncInfo)
			c.NullifierSecret[0] = 1
			c.PublicInputHash = keyStatement(t, big.NewInt(0x0a), spptest.MustNullifierPk(t, new(big.Int).SetBytes(secret[1:])), sealed)
		}, statement},
		{"statement naming a key the envelope does not seal", func(t *testing.T, c *policy.KeyRegisterCircuit) {
			secret := ringaudit.Scalar(0x07)
			secret[0] = 0
			sealed := ringaudit.DefaultKeys(t).Seal(t, secret[:], policy.NfKeyEncInfo)
			c.PublicInputHash = keyStatement(t, big.NewInt(0x0a), spptest.MustNullifierPk(t, big.NewInt(0x08)), sealed)
		}, statement},
		{"envelope sealed to another auditor", func(_ *testing.T, c *policy.KeyRegisterCircuit) {
			c.AuditorPk[1] = 0
		}, statement},
		{"secret bytes outside 0..255 packing to the same key", func(_ *testing.T, c *policy.KeyRegisterCircuit) {
			// Moving 256 between adjacent bytes keeps the key, the envelope's byte table refuses the encoding.
			c.NullifierSecret[1], c.NullifierSecret[2] = c.NullifierSecret[1].(int)-1, c.NullifierSecret[2].(int)+256
		}, []string{"base.Envelope.Seal", "policy.(*KeyRegisterCircuit).Define"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := keyEnvelope(t, big.NewInt(0x0a))
			tt.tamper(t, c)
			refusal.Require(t, test.IsSolved(&policy.KeyRegisterCircuit{}, c, ecc.BN254.ScalarField()), tt.frames...)
		})
	}
}

// The ring program verifies the key with one BSB22 commitment over private wires.
func TestKeyRegisterKey(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &policy.KeyRegisterCircuit{}, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	if got, pinned := cs.GetNbConstraints(), 36991; got != pinned {
		t.Errorf("register key constraints=%d, pinned %d", got, pinned)
	}
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
		t.Errorf("register key commitments %v", cs.GetCommitments())
	}
}
