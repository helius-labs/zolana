package ed25519

import "github.com/consensys/gnark/frontend"

func (c *curve) montBase(bits []frontend.Variable) *point {
	digits, odd, zero := c.recode(bits)
	return c.montBaseRecoded(digits, odd, zero)
}

func (c *curve) recode(bits []frontend.Variable) ([]frontend.Variable, frontend.Variable, frontend.Variable) {
	s := c.fromBits(c.fr, bits)
	odd := bits[0]
	zero := c.api.IsZero(c.api.Add(0, 0, bits...))
	return c.recodeValue(s, odd, zero, len(bits))
}
