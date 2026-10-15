package shortchecker

import "math/big"

// hostMul uses Jacobian coordinates with mixed affine additions and one final
// inversion. The formulas support general short-Weierstrass a, including the
// selected quadratic twist, and explicitly handle exceptional additions.
// https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
func hostMul(p hostPoint, s, a *big.Int) hostPoint {
	if p.x == nil || s.Sign() == 0 {
		return hostPoint{}
	}
	mod := prime()
	var bx, by, coefficient, x, y, z big.Int
	bx.Mod(p.x, mod)
	by.Mod(p.y, mod)
	coefficient.Mod(a, mod)
	if s.Sign() < 0 {
		by.Neg(&by).Mod(&by, mod)
	}
	scalar := new(big.Int).Abs(s)
	mask := new(big.Int).Sub(pow2(255), big.NewInt(1))
	var high big.Int
	nineteen := big.NewInt(19)
	// Canonical operands give a product below 2^510. Two folds using
	// 2^255 = 19 leave at most 2^255 + 360, so one subtraction canonicalizes it.
	mul := func(out, left, right *big.Int) {
		out.Mul(left, right)
		high.Rsh(out, 255)
		out.And(out, mask)
		high.Mul(&high, nineteen)
		out.Add(out, &high)
		high.Rsh(out, 255)
		out.And(out, mask)
		high.Mul(&high, nineteen)
		out.Add(out, &high)
		if out.Cmp(mod) >= 0 {
			out.Sub(out, mod)
		}
	}
	add := func(out, left, right *big.Int) {
		out.Add(left, right)
		if out.Cmp(mod) >= 0 {
			out.Sub(out, mod)
		}
	}
	sub := func(out, left, right *big.Int) {
		out.Sub(left, right)
		if out.Sign() < 0 {
			out.Add(out, mod)
		}
	}
	var tmp [13]big.Int
	double := func() {
		if z.Sign() == 0 || y.Sign() == 0 {
			z.SetInt64(0)
			return
		}
		xx, yy, yyyy, zz, z4, ss, mm, tx, ny, nz, scratch := &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &tmp[6], &tmp[7], &tmp[8], &tmp[9], &tmp[10]
		mul(xx, &x, &x)
		mul(yy, &y, &y)
		mul(yyyy, yy, yy)
		mul(zz, &z, &z)
		mul(z4, zz, zz)
		mul(ss, &x, yy)
		add(ss, ss, ss)
		add(ss, ss, ss)
		mul(mm, &coefficient, z4)
		add(scratch, xx, xx)
		add(scratch, scratch, xx)
		add(mm, mm, scratch)
		mul(tx, mm, mm)
		add(scratch, ss, ss)
		sub(tx, tx, scratch)
		sub(ny, ss, tx)
		mul(ny, mm, ny)
		add(scratch, yyyy, yyyy)
		add(scratch, scratch, scratch)
		add(scratch, scratch, scratch)
		sub(ny, ny, scratch)
		mul(nz, &y, &z)
		add(nz, nz, nz)
		x.Set(tx)
		y.Set(ny)
		z.Set(nz)
	}
	for bit := scalar.BitLen() - 1; bit >= 0; bit-- {
		double()
		if scalar.Bit(bit) == 0 {
			continue
		}
		if z.Sign() == 0 {
			x.Set(&bx)
			y.Set(&by)
			z.SetInt64(1)
			continue
		}
		zz, zzz, u, v, h, r, hh, hhh, xhh, nx, ny, nz, scratch := &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &tmp[6], &tmp[7], &tmp[8], &tmp[9], &tmp[10], &tmp[11], &tmp[12]
		mul(zz, &z, &z)
		mul(zzz, zz, &z)
		mul(u, &bx, zz)
		mul(v, &by, zzz)
		sub(h, u, &x)
		sub(r, v, &y)
		if h.Sign() == 0 {
			if r.Sign() == 0 {
				double()
			} else {
				z.SetInt64(0)
			}
			continue
		}
		mul(hh, h, h)
		mul(hhh, hh, h)
		mul(xhh, &x, hh)
		mul(nx, r, r)
		sub(nx, nx, hhh)
		add(scratch, xhh, xhh)
		sub(nx, nx, scratch)
		sub(ny, xhh, nx)
		mul(ny, r, ny)
		mul(scratch, &y, hhh)
		sub(ny, ny, scratch)
		mul(nz, &z, h)
		x.Set(nx)
		y.Set(ny)
		z.Set(nz)
	}
	if z.Sign() == 0 {
		return hostPoint{}
	}
	inverse := new(big.Int).ModInverse(&z, mod)
	if inverse == nil {
		return hostPoint{}
	}
	var z2, z3 big.Int
	mul(&z2, inverse, inverse)
	mul(&z3, &z2, inverse)
	mul(&x, &x, &z2)
	mul(&y, &y, &z3)
	return hostPoint{&x, &y}
}
