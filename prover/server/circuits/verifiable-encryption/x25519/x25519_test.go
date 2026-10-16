package x25519

import (
	"bytes"
	stdecdh "crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
)

type testCircuit struct {
	Scalar, Peer [32]frontend.Variable
	Shared       [32]frontend.Variable `gnark:",public"`
	Layout       emfield.Layout        `gnark:"-"`
}

func (c *testCircuit) Define(api frontend.API) error {
	lay := c.Layout
	if lay.NbLimbs == 0 {
		lay = defaultLayout
	}
	got := ecdh(api, c.Scalar, c.Peer, lay)
	for i := range got {
		api.AssertIsEqual(got[i], c.Shared[i])
	}
	return nil
}

func compile(t *testing.T, lay emfield.Layout) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testCircuit{Layout: lay})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v: %d constraints", lay, cs.GetNbConstraints())
	return cs
}

func assignment(scalar, peer, shared []byte) *testCircuit {
	w := new(testCircuit)
	for i := range w.Scalar {
		w.Scalar[i], w.Peer[i], w.Shared[i] = scalar[i], peer[i], shared[i]
	}
	return w
}

func solve(cs constraint.ConstraintSystem, w *testCircuit) error {
	wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	return cs.IsSolved(wit)
}

func host(scalar, peer []byte) ([]byte, error) {
	sk, err := stdecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	pk, err := stdecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return sk.ECDH(pk)
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRFC7748(t *testing.T) {
	cs := compile(t, defaultLayout)
	vectors := [][3]string{
		{"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
		{"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"},
	}
	for i, v := range vectors {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			w := assignment(decode(t, v[0]), decode(t, v[1]), decode(t, v[2]))
			if err := solve(cs, w); err != nil {
				t.Fatal(err)
			}
			w.Shared[0] = byte(w.Shared[0].(byte) ^ 1)
			if err := solve(cs, w); err == nil {
				t.Fatal("accepted wrong shared secret")
			}
		})
	}
}

func TestDifferential(t *testing.T) {
	cs := compile(t, defaultLayout)
	classes := map[int]int{}
	for i := 0; i < 32; i++ {
		s := sha256.Sum256([]byte(fmt.Sprintf("x25519 scalar %d", i)))
		p := sha256.Sum256([]byte(fmt.Sprintf("x25519 arbitrary u %d", i)))
		uBytes := bytes.Clone(p[:])
		uBytes[31] &= 127
		slices.Reverse(uBytes)
		u := new(big.Int).SetBytes(uBytes)
		rhs := new(big.Int).Mul(u, u)
		rhs.Add(rhs, new(big.Int).Mul(big.NewInt(486662), u)).Add(rhs, big.NewInt(1)).Mul(rhs, u)
		classes[big.Jacobi(rhs, prime())]++
		want, err := host(s[:], p[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := solve(cs, assignment(s[:], p[:], want)); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	if classes[1] == 0 || classes[-1] == 0 {
		t.Fatalf("missing curve/twist coverage: %v", classes)
	}
	t.Logf("curve/twist cases: %v", classes)
}

func TestLayoutSweep(t *testing.T) {
	if os.Getenv("X25519_LAYOUT_SWEEP") != "1" {
		t.Skip("set X25519_LAYOUT_SWEEP=1 to run the layout experiment")
	}
	s := sha256.Sum256([]byte("layout scalar"))
	p := sha256.Sum256([]byte("layout peer"))
	want, err := host(s[:], p[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, bits := range []int{32, 43, 51, 64, 85} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			lay := emfield.Layout{NbLimbs: (255 + bits - 1) / bits, LimbBits: bits, PieceBits: 11}
			cs := compile(t, lay)
			if err := solve(cs, assignment(s[:], p[:], want)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func littleEndian(v *big.Int) []byte {
	out := v.FillBytes(make([]byte, 32))
	slices.Reverse(out)
	return out
}

func TestEncodingAndBoundaries(t *testing.T) {
	cs := compile(t, defaultLayout)
	for _, scalarByte := range []byte{0, 0xff, 0x55, 0xaa} {
		s := bytes.Repeat([]byte{scalarByte}, 32)
		for _, n := range []int64{2, 3, 9, 18, 19} {
			p := littleEndian(big.NewInt(n))
			want, err := host(s, p)
			if err != nil {
				t.Fatal(err)
			}
			if err := solve(cs, assignment(s, p, want)); err != nil {
				t.Fatalf("scalar %x, u=%d: %v", scalarByte, n, err)
			}
			// Changing exactly the ignored scalar bits and peer bit preserves
			// the result, while all original inputs still have to be bytes.
			s2, p2 := bytes.Clone(s), bytes.Clone(p)
			s2[0] ^= 7
			s2[31] ^= 0xc0
			p2[31] ^= 0x80
			if err := solve(cs, assignment(s2, p2, want)); err != nil {
				t.Fatal(err)
			}
			if n < 19 {
				alias := littleEndian(new(big.Int).Add(prime(), big.NewInt(n)))
				if err := solve(cs, assignment(s, alias, want)); err != nil {
					t.Fatalf("noncanonical p+%d: %v", n, err)
				}
			}
		}
	}
	s := sha256.Sum256([]byte("encoding test"))
	p := littleEndian(big.NewInt(9))
	want, err := host(s[:], p)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 15, 31} {
		for _, input := range []string{"scalar", "peer", "output"} {
			w := assignment(s[:], p, want)
			switch input {
			case "scalar":
				w.Scalar[index] = int(s[index]) + 256
			case "peer":
				w.Peer[index] = int(p[index]) + 256
			case "output":
				w.Shared[index] = int(want[index]) + 256
			}
			if err := solve(cs, w); err == nil {
				t.Fatalf("accepted out-of-range %s byte %d", input, index)
			}
		}
	}
	w := assignment(s[:], p, make([]byte, 32))
	if err := solve(cs, w); err == nil {
		t.Fatal("accepted zero shared secret")
	}
	w = assignment(s[:], p, want)
	w.Scalar[1] = byte(s[1] ^ 1)
	if err := solve(cs, w); err == nil {
		t.Fatal("scalar not bound")
	}
	w = assignment(s[:], p, want)
	w.Peer[0] = 10
	if err := solve(cs, w); err == nil {
		t.Fatal("peer not bound")
	}
}

func TestLowOrder(t *testing.T) {
	cs := compile(t, defaultLayout)
	s := sha256.Sum256([]byte("low order test"))
	// The two order-eight representatives are the published libsodium/Go
	// low-order test vectors. The other encodings cover 0, 1, p-1, p, p+1.
	peers := [][]byte{
		littleEndian(big.NewInt(0)), littleEndian(big.NewInt(1)),
		decode(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
		decode(t, "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
		littleEndian(new(big.Int).Sub(prime(), big.NewInt(1))),
		littleEndian(prime()), littleEndian(new(big.Int).Add(prime(), big.NewInt(1))),
	}
	for i, p := range peers {
		for _, high := range []byte{0, 0x80} {
			p = bytes.Clone(p)
			p[31] |= high
			if _, err := host(s[:], p); err == nil {
				t.Fatalf("Go accepted low-order %d", i)
			}
			if err := solve(cs, assignment(s[:], p, make([]byte, 32))); err == nil {
				t.Fatalf("accepted low-order %d", i)
			}
		}
	}
}
