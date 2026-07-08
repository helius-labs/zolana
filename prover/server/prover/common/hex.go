package common

import "math/big"

// FeHex encodes a field element as a 0x-prefixed 32-byte hex string; nil is 0.
func FeHex(i *big.Int) string {
	if i == nil {
		return ToHex(big.NewInt(0))
	}
	return ToHex(i)
}

// FeHexSlice encodes a slice of field elements via FeHex.
func FeHexSlice(xs []*big.Int) []string {
	out := make([]string, len(xs))
	for i := range xs {
		out[i] = FeHex(xs[i])
	}
	return out
}

// FeFromHex parses a hex field element; the empty string is 0.
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

// FeFromHexSlice parses a slice of hex field elements via FeFromHex.
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
