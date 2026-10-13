package ed25519

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type verifyCircuit struct {
	PublicKey [32]frontend.Variable `gnark:",public"`
	Signature [64]frontend.Variable
	Message   []frontend.Variable `gnark:",public"`
}

func (v *verifyCircuit) Define(api frontend.API) error {
	Verify(api, Inputs{PublicKey: v.PublicKey, Signature: v.Signature, Message: v.Message})
	return nil
}
func witnessFor(message []byte) *verifyCircuit {
	seed := sha256.Sum256([]byte("ed25519 test signing seed"))
	sk := ed25519.NewKeyFromSeed(seed[:])
	sig := ed25519.Sign(sk, message)
	pk := sk.Public().(ed25519.PublicKey)
	w := &verifyCircuit{Message: make([]frontend.Variable, len(message))}
	for i, b := range pk {
		w.PublicKey[i] = b
	}
	for i, b := range sig {
		w.Signature[i] = b
	}
	for i, b := range message {
		w.Message[i] = b
	}
	return w
}
func TestVerify(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &verifyCircuit{Message: make([]frontend.Variable, 32)})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("32 B message: %d constraints", cs.GetNbConstraints())
	w := witnessFor(make([]byte, 32))
	wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(wit); err != nil {
		t.Fatal(err)
	}
}

func TestDalekCCTV(t *testing.T) {
	data, err := os.ReadFile("testdata/cctv-dalek-1.0.1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Number int    `json:"number"`
		Key    string `json:"key"`
		Sig    string `json:"sig"`
		Msg    string `json:"msg"`
		Accept bool   `json:"dalek_strict"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	compiled := map[int]constraint.ConstraintSystem{}
	for _, v := range vectors {
		cs := compiled[len(v.Msg)]
		if cs == nil {
			cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &verifyCircuit{Message: make([]frontend.Variable, len(v.Msg))})
			if err != nil {
				t.Fatal(err)
			}
			compiled[len(v.Msg)] = cs
		}
		w := &verifyCircuit{Message: make([]frontend.Variable, len(v.Msg))}
		pk, err := hex.DecodeString(v.Key)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := hex.DecodeString(v.Sig)
		if err != nil {
			t.Fatal(err)
		}
		for i, b := range pk {
			w.PublicKey[i] = b
		}
		for i, b := range sig {
			w.Signature[i] = b
		}
		for i, b := range []byte(v.Msg) {
			w.Message[i] = b
		}
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(witness)
		if (err == nil) != v.Accept {
			t.Fatalf("CCTV vector %d: dalek_strict=%v circuit error=%v", v.Number, v.Accept, err)
		}
	}
	t.Logf("%d vectors agree with ed25519-dalek 1.0.1 verify_strict", len(vectors))
}

type coreCircuit struct {
	PublicKey [32]frontend.Variable
	Signature [64]frontend.Variable
	Digest    [64]frontend.Variable
}

func (v *coreCircuit) Define(api frontend.API) error {
	verifyDigest(api, v.PublicKey, v.Signature, v.Digest)
	return nil
}
func TestCoreCost(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &coreCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Ed25519 precomputed challenge: %d constraints", cs.GetNbConstraints())
}

func TestShortVerificationEdgesAndMixedTorsion(t *testing.T) {
	data, err := os.ReadFile("testdata/scalars-dalek-4.1.3.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Torsion             int `json:"torsion"`
		Key, Scalar, Result string
		R                   string `json:"r_for_s5"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &coreCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		w := &coreCircuit{}
		for j := range w.Signature {
			w.Signature[j] = 0
		}
		for j := range w.Digest {
			w.Digest[j] = 0
		}
		w.Signature[32] = 5
		for _, part := range []struct {
			dst []frontend.Variable
			src string
		}{{w.PublicKey[:], row.Key}, {w.Signature[:32], row.R}, {w.Digest[:32], row.Scalar}} {
			raw, err := hex.DecodeString(part.src)
			if err != nil || len(raw) != len(part.dst) {
				t.Fatalf("fixture %d bad encoding", i)
			}
			for j, b := range raw {
				part.dst[j] = b
			}
		}
		wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(wit); err != nil {
			t.Fatalf("fixture%d torsion%d challenge%s: %v", i, row.Torsion, row.Scalar, err)
		}
		// Independently generated Result=[h]A also supplies R=-[h]A at
		// S=0. Exercise zero fixed-base output at h=1 in every torsion class,
		// and reject its identity R at h=0 as Solana requires.
		if row.Scalar == "0000000000000000000000000000000000000000000000000000000000000000" || row.Scalar == "0100000000000000000000000000000000000000000000000000000000000000" {
			encoded, err := hex.DecodeString(row.Result)
			if err != nil || len(encoded) != 32 {
				t.Fatalf("fixture %d bad result", i)
			}
			want := row.Scalar[0:2] == "01"
			if want {
				encoded[31] ^= 0x80
			}
			for j, b := range encoded {
				w.Signature[j] = b
			}
			w.Signature[32] = 0
			wit, err = frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			err = cs.IsSolved(wit)
			if (err == nil) != want {
				t.Fatalf("S=0 fixture %d torsion%d: accept%v error%v", i, row.Torsion, want, err)
			}
		}
	}
	t.Logf("%d scalar/torsion edge cases", len(rows))
}
