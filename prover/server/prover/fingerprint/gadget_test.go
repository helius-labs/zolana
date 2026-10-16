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

	"github.com/helius-labs/zolana/prover/server/circuits/ed25519"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/x25519"
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

// The gadget pins guard the shared short-Weierstrass ladder code against
// constraint drift independently of the rail and ring circuits around it.
var expectedGadgetFingerprints = map[string]gadgetFingerprint{
	"x25519_ecdh":      {constraints: 21227, matrix: "3c13b56e8e148325c1774d8c7361a37619eb87fbd37260386d5b43da6e552f28", serialized: "91c5ebda52ba4766d9892e18055cbd880211b80ff5f04a8a32a6d9f7acd9efbb"},
	"x25519_generator": {constraints: 5948, matrix: "e9fb1a264897a14324333153beaa1cd0c641ef4487fce46e4a4d75b66c12de20", serialized: "0d13d351e8d4d5c2be4c8dbb114a979db3d7d0b3f4ba6aec099e76166ab051e1"},
	"ed25519_verify":   {constraints: 57499, matrix: "3f4c7b6134a7b677faf9803ce61db080ff78944fec62c2f94bce90ebfbbb83c9", serialized: "b900aff6e7f562f89b2d616002f70ffdd842b946e5ceeb8cf79a08c6e2906803"},
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
