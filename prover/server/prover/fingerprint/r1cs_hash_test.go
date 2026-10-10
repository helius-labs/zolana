package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

const hashEnvelopePlaintextBytes = 16

var (
	hashSecretTag = []byte("TMES")
	hashKdfInfo   = []byte("TMEC")
)

type hashAgreeKeyCircuit struct {
	EphemeralSk [32]frontend.Variable
	RecipientPk [65]frontend.Variable
	Packed      [6]frontend.Variable `gnark:",public"`
}

func (c *hashAgreeKeyCircuit) Define(api frontend.API) error {
	k := p256.ComputeKeyAgreement(api, c.EphemeralSk, c.RecipientPk)
	for i, v := range []frontend.Variable{k.RecipientLo, k.RecipientHi, k.EphemeralLo, k.EphemeralHi, k.SharedLo, k.SharedHi} {
		api.AssertIsEqual(v, c.Packed[i])
	}
	return nil
}

type hashDerivePublicKeyCircuit struct {
	Sk         [32]frontend.Variable
	SharedX    [32]frontend.Variable `gnark:",public"`
	Compressed [33]frontend.Variable `gnark:",public"`
	Lo, Hi     frontend.Variable     `gnark:",public"`
}

func (c *hashDerivePublicKeyCircuit) Define(api frontend.API) error {
	key := p256.DerivePublicKey(api, c.Sk)
	lo, hi := key.Packed(api)
	api.AssertIsEqual(lo, c.Lo)
	api.AssertIsEqual(hi, c.Hi)
	self := p256.SelfAgreeKey(api, key)
	for i := range self.SharedX {
		api.AssertIsEqual(self.SharedX[i], c.SharedX[i])
	}
	for i := range self.PublicKey {
		api.AssertIsEqual(self.PublicKey[i], c.Compressed[i])
	}
	return nil
}

type hashEnvelopeCircuit struct {
	EphemeralSk [32]frontend.Variable
	RecipientPk [65]frontend.Variable
	Plaintext   [hashEnvelopePlaintextBytes]frontend.Variable
	RecipientLo frontend.Variable                             `gnark:",public"`
	RecipientHi frontend.Variable                             `gnark:",public"`
	EphemeralLo frontend.Variable                             `gnark:",public"`
	EphemeralHi frontend.Variable                             `gnark:",public"`
	Ciphertext  [hashEnvelopePlaintextBytes]frontend.Variable `gnark:",public"`
}

func (c *hashEnvelopeCircuit) Define(api frontend.API) error {
	encrypted := ve.Envelope{
		SecretTag:   hashSecretTag,
		KdfInfo:     hashKdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.RecipientPk,
		Plaintext:   c.Plaintext[:],
	}.Encrypt(api)
	api.AssertIsEqual(encrypted.RecipientLo, c.RecipientLo)
	api.AssertIsEqual(encrypted.RecipientHi, c.RecipientHi)
	api.AssertIsEqual(encrypted.EphemeralLo, c.EphemeralLo)
	api.AssertIsEqual(encrypted.EphemeralHi, c.EphemeralHi)
	for i, b := range encrypted.Ciphertext {
		api.AssertIsEqual(b, c.Ciphertext[i])
	}
	return nil
}

// hashEnvelopeMergeCircuit is the envelope as spp_merge/default.go instantiates
// it: merge's tag and KDF label, the 40-byte plaintext, the first nullifier as
// Context, and the elements and blinding merge derives from it.
type hashEnvelopeMergeCircuit struct {
	EphemeralSk [32]frontend.Variable
	RecipientPk [65]frontend.Variable
	Plaintext   [mergeshared.MergeCiphertextBytes]frontend.Variable
	Context     frontend.Variable
	Elements    [4]frontend.Variable `gnark:",public"`
	Blinding    frontend.Variable    `gnark:",public"`
}

func (c *hashEnvelopeMergeCircuit) Define(api frontend.API) error {
	encrypted := ve.Envelope{
		SecretTag:   mergeshared.MergeSecretTag,
		KdfInfo:     mergeshared.MergeKdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.RecipientPk,
		Plaintext:   c.Plaintext[:],
		Context:     c.Context,
	}.Encrypt(api)
	for i, e := range mergeshared.EnvelopePublicElements(api, encrypted) {
		api.AssertIsEqual(e, c.Elements[i])
	}
	api.AssertIsEqual(mergeshared.MergeDerivedBlinding(api, encrypted.SharedSecret), c.Blinding)
	return nil
}

func structuralDigest(cs constraint.ConstraintSystem) string {
	h := sha256.New()
	put := func(v ...int) {
		for _, x := range v {
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(x))
			h.Write(buf[:])
		}
	}
	internal, secret, public := cs.GetNbVariables()
	put(cs.GetNbConstraints(), public, secret, internal, cs.GetNbCoefficients(), cs.GetNbInstructions())
	resolver, ok := cs.(constraint.Resolver)
	if !ok {
		panic("constraint system does not resolve coefficients")
	}
	for i := 0; i < cs.GetNbCoefficients(); i++ {
		h.Write([]byte(resolver.CoeffToString(i)))
		h.Write([]byte{0})
	}
	if commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments); ok {
		put(len(commitments))
		for _, c := range commitments {
			put(c.CommitmentIndex, c.NbPublicCommitted, len(c.PublicAndCommitmentCommitted), len(c.PrivateCommitted))
			put(c.PublicAndCommitmentCommitted...)
			put(c.PrivateCommitted...)
		}
	}
	r, ok := cs.(interface{ GetR1Cs() []constraint.R1C })
	if !ok {
		panic("not an R1CS")
	}
	linear := func(l constraint.LinearExpression) {
		put(len(l))
		for _, t := range l {
			put(int(t.CID), int(t.VID))
		}
	}
	for _, c := range r.GetR1Cs() {
		linear(c.L)
		linear(c.R)
		linear(c.O)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// TestWriteR1CSHashes records digests of the verifiable-encryption constraint
// systems so extraction-only changes can be checked against a base revision.
func TestWriteR1CSHashes(t *testing.T) {
	out := os.Getenv("R1CS_HASH_OUT")
	if out == "" {
		t.Skip("R1CS_HASH_OUT not set")
	}
	circuits := []struct {
		name    string
		circuit frontend.Circuit
	}{
		{"agree_key", &hashAgreeKeyCircuit{}},
		{"derive_public_key", &hashDerivePublicKeyCircuit{}},
		{"envelope_16", &hashEnvelopeCircuit{}},
		{"envelope_merge_40", &hashEnvelopeMergeCircuit{}},
	}
	var lines []string
	for _, c := range circuits {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c.circuit)
		if err != nil {
			t.Fatalf("compile %s: %v", c.name, err)
		}
		var buf bytes.Buffer
		if _, err := cs.WriteTo(&buf); err != nil {
			t.Fatalf("serialize %s: %v", c.name, err)
		}
		lines = append(lines, fmt.Sprintf("%s constraints=%d bytes=%x structure=%s", c.name, cs.GetNbConstraints(), sha256.Sum256(buf.Bytes()), structuralDigest(cs)))
	}
	if err := os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
