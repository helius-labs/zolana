package base

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Count is a witnessed count in [first, first+n) and the slot flags it selects.
type Count struct {
	// OneHot[k] is set for the count first+k.
	OneHot []frontend.Variable
	// Active[i] is set for every slot i below the count.
	Active []frontend.Variable
	first  int
}

func SelectCount(api frontend.API, count frontend.Variable, first, n int) Count {
	c := Count{OneHot: make([]frontend.Variable, n), Active: make([]frontend.Variable, first+n-1), first: first}
	sum := frontend.Variable(0)
	for k := range c.OneHot {
		c.OneHot[k] = api.IsZero(api.Sub(count, first+k))
		sum = api.Add(sum, c.OneHot[k])
	}
	// Exactly one candidate equals the count, a count outside [first, first+n) sets no flag.
	api.AssertIsEqual(sum, 1)
	active := frontend.Variable(0)
	for i := len(c.Active) - 1; i >= 0; i-- {
		active = api.Add(active, c.OneHot[i+1-first])
		c.Active[i] = active
	}
	return c
}

// HashPrefix4 is gadget.HashChain4 over values[:k+1] when OneHot[k] is set, the caller fixes k through a length the program reads.
func HashPrefix4(api frontend.API, values []frontend.Variable, c Count) frontend.Variable {
	if len(c.OneHot) != len(values) || c.first != 1 {
		panic("base: hash prefix needs one selector per prefix length from 1")
	}
	last := -1
	for k, selected := range c.OneHot {
		if !gadget.IsConstantZero(api, selected) {
			last = k
		}
	}
	head := values[0]
	selected := api.Mul(c.OneHot[0], head)
	for start := 1; start <= last; start += 3 {
		end := min(start+3, len(values))
		for stop := start + 1; stop <= end; stop++ {
			// A full group is the head of every later prefix.
			nextHead := stop == end && stop <= last
			if gadget.IsConstantZero(api, c.OneHot[stop-1]) && !nextHead {
				continue
			}
			group := []frontend.Variable{head, 0, 0, 0}
			copy(group[1:], values[start:stop])
			hash := gadget.PoseidonHash(api, group)
			selected = api.Add(selected, api.Mul(c.OneHot[stop-1], hash))
			if stop == end {
				head = hash
			}
		}
	}
	return selected
}

func IsNonZero(api frontend.API, value frontend.Variable) frontend.Variable {
	return api.Sub(1, api.IsZero(value))
}

// IsAny is the OR of bits, api.Or refuses a term that is no bit.
func IsAny(api frontend.API, bits ...frontend.Variable) frontend.Variable {
	result := frontend.Variable(0)
	for _, bit := range bits {
		result = api.Or(result, bit)
	}
	return result
}

func ConstBytes(s string) []frontend.Variable {
	out := make([]frontend.Variable, len(s))
	for i := range s {
		out[i] = s[i]
	}
	return out
}
