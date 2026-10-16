package shortchecker

import "math/big"

func hostMulAffine(p hostPoint, s, a *big.Int) hostPoint {
	r := hostPoint{}
	for i := s.BitLen() - 1; i >= 0; i-- {
		r = hostAdd(r, r, a)
		if s.Bit(i) != 0 {
			r = hostAdd(r, p, a)
		}
	}
	return r
}
