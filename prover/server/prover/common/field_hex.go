package common

import "math/big"

// FeHex encodes a field element for the wire; a nil value encodes as zero so an
// unset optional parameter never serializes as an empty string.
func FeHex(i *big.Int) string {
	if i == nil {
		return ToHex(big.NewInt(0))
	}
	return ToHex(i)
}

// FeHexSlice encodes every element with FeHex.
func FeHexSlice(xs []*big.Int) []string {
	out := make([]string, len(xs))
	for i := range xs {
		out[i] = FeHex(xs[i])
	}
	return out
}

// FeFromHex decodes a wire field element; an empty string decodes as zero.
// Callers that must distinguish an omitted field from zero check the string
// before calling.
func FeFromHex(s string) (*big.Int, error) {
	v := new(big.Int)
	if s == "" {
		return v, nil
	}
	if err := FromHex(v, s); err != nil {
		return nil, err
	}
	return v, nil
}

// FeFromHexSlice decodes every element with FeFromHex.
func FeFromHexSlice(ss []string) ([]*big.Int, error) {
	out := make([]*big.Int, len(ss))
	for i, s := range ss {
		v, err := FeFromHex(s)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
