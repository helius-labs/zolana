package gadget

import "github.com/consensys/gnark/frontend"

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
	// 1. Each flag is set exactly when the count equals its candidate.
	sum := frontend.Variable(0)
	for k := range c.OneHot {
		c.OneHot[k] = api.IsZero(api.Sub(count, first+k))
		sum = api.Add(sum, c.OneHot[k])
	}
	// 2. Exactly one candidate equals the count, a count outside [first, first+n) sets no flag.
	api.AssertIsEqual(sum, 1)
	// 3. Slot i is active when a flag at or above count i+1 is set.
	active := frontend.Variable(0)
	for i := len(c.Active) - 1; i >= 0; i-- {
		active = api.Add(active, c.OneHot[i+1-first])
		c.Active[i] = active
	}
	return c
}

// Candidate is the count OneHot[k] flags.
func (c Count) Candidate(k int) int {
	return c.first + k
}

// HashPrefix4 is HashChain4 over values[:k+1] when oneHot sets only flag k, a flag fixed to zero hashes nothing.
func HashPrefix4(api frontend.API, values, oneHot []frontend.Variable) frontend.Variable {
	if len(oneHot) != len(values) {
		panic("gadget: hash prefix needs one flag per prefix length")
	}
	// 1. The last flag the circuit can set bounds the groups it hashes.
	last := -1
	for k, selected := range oneHot {
		if !IsConstantZero(api, selected) {
			last = k
		}
	}
	// 2. Each prefix extends the chain head of its full groups, the one set flag keeps its hash.
	head := values[0]
	selected := api.Mul(oneHot[0], head)
	for start := 1; start <= last; start += 3 {
		end := min(start+3, len(values))
		for stop := start + 1; stop <= end; stop++ {
			// A full group is the head of every later prefix.
			nextHead := stop == end && stop <= last
			if IsConstantZero(api, oneHot[stop-1]) && !nextHead {
				continue
			}
			group := []frontend.Variable{head, 0, 0, 0}
			copy(group[1:], values[start:stop])
			hash := PoseidonHash(api, group)
			selected = api.Add(selected, api.Mul(oneHot[stop-1], hash))
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
