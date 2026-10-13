package ed25519

import "github.com/consensys/gnark/frontend"

func (c *curve) montBase(bits []frontend.Variable) *point {
	digits, odd, zero := c.recode(bits)
	return c.montBaseRecoded(digits, odd, zero)
}
