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
}

func SelectCount(api frontend.API, count frontend.Variable, first, n int) Count {
	c := Count{OneHot: make([]frontend.Variable, n), Active: make([]frontend.Variable, first+n-1)}
	sum := frontend.Variable(0)
	for k := range c.OneHot {
		c.OneHot[k] = api.IsZero(api.Sub(count, first+k))
		sum = api.Add(sum, c.OneHot[k])
	}
	api.AssertIsEqual(sum, 1)
	active := frontend.Variable(0)
	for i := len(c.Active) - 1; i >= 0; i-- {
		active = api.Add(active, c.OneHot[i+1-first])
		c.Active[i] = active
	}
	return c
}

// HashPrefix4 is gadget.HashChain4 over the first count values, for a count from 1.
func HashPrefix4(api frontend.API, values []frontend.Variable, c Count) frontend.Variable {
	head := values[0]
	selected := api.Mul(c.OneHot[0], head)
	for start := 1; start < len(values); start += 3 {
		end := min(start+3, len(values))
		for stop := start + 1; stop <= end; stop++ {
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

// ExtendHashPrefix folds the first count values into head, as create_hash_chain_from_slice does.
func ExtendHashPrefix(api frontend.API, head frontend.Variable, values []frontend.Variable, c Count) frontend.Variable {
	selected := api.Mul(c.OneHot[0], head)
	for k, value := range values {
		head = gadget.PoseidonHash(api, []frontend.Variable{head, value})
		selected = api.Add(selected, api.Mul(c.OneHot[k+1], head))
	}
	return selected
}

func NonZero(api frontend.API, value frontend.Variable) frontend.Variable {
	return api.Sub(1, api.IsZero(value))
}

func AnyOf(api frontend.API, terms ...frontend.Variable) frontend.Variable {
	result := frontend.Variable(0)
	for _, term := range terms {
		result = api.Or(result, term)
	}
	return result
}

func CheckBytes(rc frontend.Rangechecker, groups ...[]frontend.Variable) {
	for _, group := range groups {
		for _, b := range group {
			rc.Check(b, 8)
		}
	}
}

func ConstBytes(s string) []frontend.Variable {
	out := make([]frontend.Variable, len(s))
	for i := range s {
		out[i] = s[i]
	}
	return out
}
