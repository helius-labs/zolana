package x25519

import (
	"math/big"
	"testing"
)

// These are the only values in the clamped s=k/8 range that meet any of
// s=±1, ±3, ±1/3 modulo either prime subgroup order. A joint odd-multiple
// table has P=[3]R here, so its ordinary incomplete additions collide.
func TestExceptionalThirdScalars(t *testing.T) {
	curveOrder, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	twistOrder := new(big.Int).Add(new(big.Int).Lsh(prime(), 1), big.NewInt(2))
	twistOrder.Sub(twistOrder, new(big.Int).Lsh(new(big.Int).Set(curveOrder), 3)).Rsh(twistOrder, 2)
	low := new(big.Int).Lsh(big.NewInt(1), 251)
	high := new(big.Int).Lsh(big.NewInt(1), 252)
	cs := compile(t, defaultLayout)
	for _, branch := range []struct {
		name   string
		order  *big.Int
		scalar string
	}{
		{"curve", curveOrder, "486a749a8c106280cc992865a334a5c455555555555555555555555555555555"},
		{"twist", twistOrder, "504036101e9a482ade108245077605e654555555555555555555555555555555"},
	} {
		t.Run(branch.name, func(t *testing.T) {
			third := new(big.Int).ModInverse(big.NewInt(3), branch.order)
			seen := 0
			for _, v := range []*big.Int{big.NewInt(1), big.NewInt(3), third} {
				for _, s := range []*big.Int{v, new(big.Int).Sub(branch.order, v)} {
					if s.Cmp(low) >= 0 && s.Cmp(high) < 0 {
						seen++
						if s.Cmp(third) != 0 {
							t.Fatal("unexpected exceptional scalar", s)
						}
					}
				}
			}
			if seen != 1 {
				t.Fatal("expected exactly one exceptional scalar", seen)
			}
			k := new(big.Int).Lsh(new(big.Int).Set(third), 3)
			scalar := littleEndian(k)
			if string(scalar) != string(decode(t, branch.scalar)) {
				t.Fatal("exceptional scalar vector changed")
			}
			// Check its intended curve and the opposite branch, plus nearby
			// nonexceptional scalars so equality guards cannot over-trigger.
			for _, delta := range []int64{-8, 0, 8} {
				scalar := littleEndian(new(big.Int).Add(k, big.NewInt(delta)))
				for _, u := range []int64{2, 9} {
					peer := littleEndian(big.NewInt(u))
					want, err := host(scalar, peer)
					if err != nil {
						t.Fatal(err)
					}
					if err := solve(cs, assignment(scalar, peer, want)); err != nil {
						t.Errorf("delta %d, u=%d: %v", delta, u, err)
					}
				}
			}
		})
	}
}

// Small rational relations exercise every odd-multiple table and final
// parity correction, including equal-point additions that random inputs miss.
func TestSmallRationalScalars(t *testing.T) {
	curveOrder, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	twistOrder := new(big.Int).Add(new(big.Int).Lsh(prime(), 1), big.NewInt(2))
	twistOrder.Sub(twistOrder, new(big.Int).Lsh(new(big.Int).Set(curveOrder), 3)).Rsh(twistOrder, 2)
	low, high := new(big.Int).Lsh(big.NewInt(1), 251), new(big.Int).Lsh(big.NewInt(1), 252)
	cs := compile(t, defaultLayout)
	for _, branch := range []struct {
		name string
		n    *big.Int
		u    int64
	}{{"curve", curveOrder, 9}, {"twist", twistOrder, 2}} {
		seen := map[string]bool{}
		for a := int64(-16); a <= 16; a++ {
			for b := int64(1); b <= 16; b++ {
				s := new(big.Int).Mod(new(big.Int).Mul(big.NewInt(a), new(big.Int).ModInverse(big.NewInt(b), branch.n)), branch.n)
				if s.Cmp(low) < 0 || s.Cmp(high) >= 0 || seen[s.String()] {
					continue
				}
				seen[s.String()] = true
				scalar := littleEndian(new(big.Int).Lsh(s, 3))
				peer := littleEndian(big.NewInt(branch.u))
				want, e := host(scalar, peer)
				if e != nil {
					t.Fatal(e)
				}
				if e = solve(cs, assignment(scalar, peer, want)); e != nil {
					t.Errorf("%s %d/%d scalar %x: %v", branch.name, a, b, scalar, e)
				}
			}
		}
	}
}
