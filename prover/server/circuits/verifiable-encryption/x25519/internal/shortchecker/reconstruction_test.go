package shortchecker

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/algebra/lattice"
	"math/big"
	"testing"
)

func TestReconstructionFits127Bits(t *testing.T) {
	for _, twist := range []bool{false, true} {
		n := order(twist)
		h := new(big.Int).Sqrt(n)
		bound := pow2(127)
		if h.Cmp(bound) >= 0 || new(big.Int).Mul(bound, h).Cmp(n) <= 0 {
			t.Fatal("127-bit reconstruction bound fails", twist)
		}
		samples := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1)), new(big.Int).ModInverse(big.NewInt(3), n), new(big.Int).ModInverse(big.NewInt(6), n)}
		for i := 0; i < 256; i++ {
			b := sha256.Sum256([]byte(fmt.Sprintf("x25519 reconstruction %t %d", twist, i)))
			samples = append(samples, new(big.Int).Mod(new(big.Int).SetBytes(b[:]), n))
		}
		for _, s := range samples {
			v := lattice.NewReconstructor(n).RationalReconstruct(s)
			if v[0].BitLen() > 127 || v[1].BitLen() > 127 {
				t.Fatal("reconstruction exceeds127bits", twist, s, v)
			}
		}
	}
}
