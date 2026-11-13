package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/ed25519"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
)

type ecdhGadget struct {
	Scalar, Peer [32]frontend.Variable
	Shared       [32]frontend.Variable `gnark:",public"`
}

func (c *ecdhGadget) Define(api frontend.API) error {
	got := x25519.ECDH(api, c.Scalar, c.Peer)
	for i := range got {
		api.AssertIsEqual(got[i], c.Shared[i])
	}
	return nil
}

type generatorGadget struct {
	Scalar [32]frontend.Variable
	Public [32]frontend.Variable `gnark:",public"`
}

func (c *generatorGadget) Define(api frontend.API) error {
	got := x25519.ScalarMulGenerator(api, c.Scalar)
	for i := range got {
		api.AssertIsEqual(got[i], c.Public[i])
	}
	return nil
}

type ed25519Gadget struct {
	PublicKey [32]frontend.Variable `gnark:",public"`
	Signature [64]frontend.Variable
	Message   [32]frontend.Variable `gnark:",public"`
}

func (c *ed25519Gadget) Define(api frontend.API) error {
	ed25519.Verify(api, ed25519.Inputs{PublicKey: c.PublicKey, Signature: c.Signature, Message: c.Message[:]})
	return nil
}

type gadgetFingerprint struct {
	constraints int
	// matrix hashes the R1CS matrices with resolved coefficients and wire ids.
	// serialized hashes the whole constraint system, hint ids included.
	matrix, serialized string
}

func fingerprintGadget(t *testing.T, circuit frontend.Circuit) gadgetFingerprint {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	var serialized bytes.Buffer
	if _, err := cs.WriteTo(&serialized); err != nil {
		t.Fatal(err)
	}
	matrix := sha256.New()
	internal, secret, public := cs.GetNbVariables()
	fmt.Fprintf(matrix, "%d %d %d\n", internal, secret, public)
	resolver := cs.(constraint.Resolver)
	for _, c := range cs.(constraint.R1CS[constraint.U64]).GetR1Cs() {
		for _, le := range []constraint.LinearExpression{c.L, c.R, c.O} {
			for _, term := range le {
				binary.Write(matrix, binary.LittleEndian, term.VID)
				matrix.Write([]byte(resolver.CoeffToString(int(term.CID))))
			}
			matrix.Write([]byte{'|'})
		}
		matrix.Write([]byte{'\n'})
	}
	return gadgetFingerprint{
		constraints: cs.GetNbConstraints(),
		matrix:      hex.EncodeToString(matrix.Sum(nil)),
		serialized:  fmt.Sprintf("%x", sha256.Sum256(serialized.Bytes())),
	}
}

// Pins each gadget independently of the circuits that use it.
var expectedGadgetFingerprints = map[string]gadgetFingerprint{
	"x25519_ecdh":      {constraints: 23859, matrix: "0c710c07458b51b182b2131df751eb84272b29804a9bd4a0cd9b055ddc1b3d25", serialized: "0ded6ed638f0fdfeb970d4da27b68a44f166ef315708920836ab6ab29ec201c6"},
	"x25519_generator": {constraints: 5948, matrix: "e9fb1a264897a14324333153beaa1cd0c641ef4487fce46e4a4d75b66c12de20", serialized: "1ba9ead4fcc3920d2df7a5395aa4e5c28462074455bad24d6c20abdea3e3b49d"},
	"ed25519_verify":   {constraints: 53320, matrix: "f86e6c921c366ec8380697ba013aa547e5f0dbc4fb0f76806cbc812824f8b4fc", serialized: "a8254917fb729a3bf50873fb4d627d2e46c06f2b7f5c1b26bbed60834f5a2eb1"},
}

func TestGadgetFingerprints(t *testing.T) {
	got := map[string]gadgetFingerprint{
		"x25519_ecdh":      fingerprintGadget(t, &ecdhGadget{}),
		"x25519_generator": fingerprintGadget(t, &generatorGadget{}),
		"ed25519_verify":   fingerprintGadget(t, &ed25519Gadget{}),
	}
	if os.Getenv("UPDATE_FINGERPRINTS") == "1" {
		for name, fp := range got {
			fmt.Printf("\t%q: {constraints: %d, matrix: %q, serialized: %q},\n", name, fp.constraints, fp.matrix, fp.serialized)
		}
		t.Skip("UPDATE_FINGERPRINTS=1: printed current gadget fingerprints")
	}
	for name, want := range expectedGadgetFingerprints {
		if have := got[name]; have != want {
			t.Errorf("gadget %s changed: %+v -> %+v", name, want, have)
		}
	}
}
