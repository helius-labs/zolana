package transcript

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cryptohash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	fieldhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/test"
)

type parityCircuit struct {
	Width                             int `gnark:"-"`
	Values                            []frontend.Variable
	Prefix, Complete, Extended, Empty frontend.Variable `gnark:",public"`
}

func (c *parityCircuit) Define(api frontend.API) error {
	h, err := fieldhash.GetFieldHasher(NameForWidth(c.Width), api)
	if err != nil {
		return err
	}
	cut := len(c.Values) / 2
	h.Write(c.Values[:cut]...)
	api.AssertIsEqual(h.Sum(), c.Prefix)
	api.AssertIsEqual(h.Sum(), c.Prefix)
	h.Write(c.Values[cut:]...)
	api.AssertIsEqual(h.Sum(), c.Complete)
	h.Write(0)
	api.AssertIsEqual(h.Sum(), c.Extended)
	h.Reset()
	api.AssertIsEqual(h.Sum(), c.Empty)
	return nil
}

func nativeDigest(width int, values []frontend.Variable) *big.Int {
	h := NewNativeWithWidth(width)
	for _, value := range values {
		var field fr.Element
		field.SetBigInt(value.(*big.Int))
		data := field.Bytes()
		if _, err := h.Write(data[:]); err != nil {
			panic(err)
		}
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

func TestNativeCircuitParity(t *testing.T) {
	Register()
	for _, width := range widths {
		t.Run(NameForWidth(width), func(t *testing.T) {
			rate := width - capacity
			for _, size := range []int{0, 1, rate - 2, rate - 1, rate, rate + 1, 2*rate - 1, 2 * rate, 2*rate + 1, 64} {
				t.Run(fmt.Sprint(size), func(t *testing.T) {
					values := make([]frontend.Variable, size)
					for i := range values {
						values[i] = big.NewInt(int64(i * i))
					}
					if size > 1 {
						values[1] = new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
					}
					witness := parityCircuit{
						Width:  width,
						Values: values,
						Prefix: nativeDigest(width, values[:size/2]), Complete: nativeDigest(width, values),
						Extended: nativeDigest(width, append(append([]frontend.Variable{}, values...), big.NewInt(0))),
						Empty:    nativeDigest(width, nil),
					}
					if err := test.IsSolved(&parityCircuit{Width: width, Values: make([]frontend.Variable, size)}, &witness, ecc.BN254.ScalarField()); err != nil {
						t.Fatalf("size %d: %v", size, err)
					}
				})
			}
		})
	}
}

func TestNativeFramingAndFinalization(t *testing.T) {
	Register()
	for _, width := range widths {
		t.Run(NameForWidth(width), func(t *testing.T) {
			checkNativeFraming(t, width)
		})
	}
}

func checkNativeFraming(t *testing.T, width int) {
	h := cryptohash.NewHash(NameForWidth(width) + "_BN254")
	empty := bytes.Clone(h.Sum(nil))
	if n, err := h.Write([]byte{0}); n != 1 || err != nil {
		t.Fatalf("zero separator: %d %v", n, err)
	}
	oneZero := bytes.Clone(h.Sum(nil))
	if bytes.Equal(empty, oneZero) || !bytes.Equal(oneZero, h.Sum(nil)) {
		t.Fatal("finalization does not bind length or mutates state")
	}
	h2 := NewNativeWithWidth(width)
	if _, err := h2.Write(make([]byte, fr.Bytes)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oneZero, h2.Sum(nil)) {
		t.Fatal("zero separator differs from zero field")
	}
	if n, err := h.Write(nil); n != 0 || err != nil || !bytes.Equal(oneZero, h.Sum(nil)) {
		t.Fatal("empty write changed state")
	}
	for _, bad := range [][]byte{{1}, make([]byte, fr.Bytes-1), fr.Modulus().FillBytes(make([]byte, fr.Bytes))} {
		if _, err := h.Write(bad); err == nil || !bytes.Equal(oneZero, h.Sum(nil)) {
			t.Fatal("malformed field accepted or changed state")
		}
	}
	badBatch := append(make([]byte, fr.Bytes), fr.Modulus().FillBytes(make([]byte, fr.Bytes))...)
	if _, err := h.Write(badBatch); err == nil || !bytes.Equal(oneZero, h.Sum(nil)) {
		t.Fatal("malformed batch changed state")
	}
	rate := width - capacity
	for _, size := range []int{rate - 2, rate - 1, rate, rate + 1, 2*rate - 1, 2 * rate, 2*rate + 1} {
		h.Reset()
		if _, err := h.Write(make([]byte, size*fr.Bytes)); err != nil {
			t.Fatal(err)
		}
		before := bytes.Clone(h.Sum(nil))
		if _, err := h.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(before, h.Sum(nil)) {
			t.Fatalf("zero extension collision at size %d", size)
		}
	}
	h.Reset()
	if !bytes.Equal(empty, h.Sum(nil)) {
		t.Fatal("reset differs from new hasher")
	}
	if got := h.Sum([]byte{9}); len(got) != fr.Bytes+1 || got[0] != 9 {
		t.Fatal("Sum discarded its prefix")
	}
	data := append(new(big.Int).Sub(fr.Modulus(), big.NewInt(1)).FillBytes(make([]byte, fr.Bytes)), make([]byte, fr.Bytes)...)
	whole, split := NewNativeWithWidth(width), NewNativeWithWidth(width)
	if _, err := whole.Write(data); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(data); i += fr.Bytes {
		if _, err := split.Write(data[i : i+fr.Bytes]); err != nil {
			t.Fatal(err)
		}
		split.Sum(nil)
	}
	if !bytes.Equal(whole.Sum(nil), split.Sum(nil)) {
		t.Fatal("field batching or intermediate Sum changed digest")
	}
}

func TestWidthDomains(t *testing.T) {
	names, digests := map[string]bool{}, map[string]bool{}
	for _, width := range widths {
		name := NameForWidth(width)
		domain := new(big.Int).SetBytes([]byte(name))
		if domain.Cmp(fr.Modulus()) >= 0 || names[name] {
			t.Fatal("domain is repeated or noncanonical")
		}
		names[name] = true
		digest := string(NewNativeWithWidth(width).Sum(nil))
		if digests[digest] {
			t.Fatal("widths share empty digest")
		}
		digests[digest] = true
	}
	if NameForWidth(defaultWidth) != Name {
		t.Fatal("default registry name differs")
	}
}

func TestRejectsWrongDigest(t *testing.T) {
	Register()
	for _, width := range widths {
		values := []frontend.Variable{big.NewInt(9)}
		witness := parityCircuit{
			Width: width, Values: values, Prefix: nativeDigest(width, nil), Complete: 1,
			Extended: nativeDigest(width, append(values, big.NewInt(0))), Empty: nativeDigest(width, nil),
		}
		if test.IsSolved(&parityCircuit{Width: width, Values: make([]frontend.Variable, 1)}, &witness, ecc.BN254.ScalarField()) == nil {
			t.Fatalf("width %d accepted wrong digest", width)
		}
	}
}
