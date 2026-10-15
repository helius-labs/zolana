// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0 (the "License").
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shortchecker

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/internal/lookup"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/internal/r1c"
)

// init registers untrusted decomposition, multiplication and ladder hints.
// Their relations are enforced by scalarMulLadder and its step constraints.
func init() {
	solver.RegisterHint(shortDecomposeScalarHint, shortScalarMulHint, shortImplicitChordHint, shortImplicitSecondSlopeHint)
}

const (
	halfScalarBits = 129
	packedXGroup   = 2
)

// nativeValue projects an emulated integer into the native field.
// It is injective only with a proven integer range below that field modulus.
// scalarMulChecked uses it on s<2^252, which fits BN254 Fr.
func (c *curve) nativeValue(e *fpElement) frontend.Variable {
	sum := frontend.Variable(0)
	for i, l := range e.Limbs() {
		sum = c.api.Add(sum, c.api.Mul(l, pow2(c.lay.LimbBits*i)))
	}
	return sum
}

// assertDistinctX rejects equality modulo p between reduced coordinates.
// Reduced widths must already be constrained. Since coordinates lie below
// 2^255, checking integer differences 0 and +/-p covers every alias.
func (c *curve) assertDistinctX(a, b *fpElement) {
	// 1. Require reduced bounds and pack each coordinate into two small chunks.
	widths := c.fp.ReducedWidths()
	if !a.IsReduced(widths) || !b.IsReduced(widths) {
		panic("x25519: distinct point guard needs reduced coordinates")
	}
	pack := func(e *fpElement, start, end int) frontend.Variable {
		out := frontend.Variable(0)
		for i := start; i < end; i++ {
			out = c.api.Add(out, c.api.Mul(e.Limbs()[i], pow2((i-start)*c.lay.LimbBits)))
		}
		return out
	}
	cut := (c.lay.NbLimbs + 1) / 2
	B := pow2(cut * c.lay.LimbBits)
	mask := new(big.Int).Sub(B, big.NewInt(1))
	p := prime()
	pl := new(big.Int).And(p, mask)
	ph := new(big.Int).Rsh(p, uint(cut*c.lay.LimbBits))
	lo := c.api.Sub(pack(a, 0, cut), pack(b, 0, cut))
	hi := c.api.Sub(pack(a, cut, c.lay.NbLimbs), pack(b, cut, c.lay.NbLimbs))
	// For reduced noncanonical coordinates in [0,2^255), equal Fp values
	// differ by 0 or +/-p. Since p=2^255-19, only these three packed pairs are
	// possible. A low-half borrow would need a high difference of +/-2^(255-cut).
	// 2. Exclude all three possible equality aliases using checked inverses.
	for _, k := range []int64{-1, 0, 1} {
		dl := c.api.Sub(lo, new(big.Int).Mul(big.NewInt(k), pl))
		dh := c.api.Sub(hi, new(big.Int).Mul(big.NewInt(k), ph))
		inv, err := c.api.Compiler().NewHint(shortPackedNonzeroHint, 2, dl, dh)
		if err != nil {
			panic(err)
		}
		r1c.AssertProduct(c.api, inv[1], dh, c.api.Sub(1, c.api.Mul(inv[0], dl)))
	}
}

// quadrupleAndAddLazy constrains one lazy 4A+T ladder step. T must be a
// validated subgroup point. These equations are not a standalone addition
// gadget. Their soundness also requires the output-distinctness guard and
// equality of the final ladder accumulator to a known on-curve target.
// The final equality propagates curve membership backwards through each step,
// fixing its hidden slopes even when the chord inputs have equal X coordinates.
func (c *curve) quadrupleAndAddLazy(a, t *point) *point {
	fp := c.fp
	// 1. Constrain the tangent at A and form the implicit doubled point D.
	lambda0 := c.tangent(a)
	xD := fp.Lazy(T(1, lambda0, lambda0), T(-2, a.X))
	tMinusD := fp.Sub(t.X, xD)
	// 2. Constrain the chord from D to T, allowing the equal-point case.
	lambda1 := c.slope(shortImplicitChordHint, 1, nil, lambda0, a.X, xD, a.Y, t.X, t.Y, c.a)[0]
	yChord := fp.Lazy(T(1, lambda1, tMinusD))
	fp.AssertZeroProjected(T(1, yChord), T(1, lambda0, fp.Sub(a.X, xD)), T(-1, a.Y), T(-1, t.Y))
	x2 := fp.Lazy(T(1, lambda1, lambda1), T(-1, xD), T(-1, t.X))
	// 3. Constrain the second slope correction and exclude output X=T.X.
	mu := c.slope(shortImplicitSecondSlopeHint, 1, nil, lambda0, a.X, xD, a.Y, x2)[0]
	fp.AssertZeroProjected(T(1, mu, fp.Sub(x2, xD)), T(2, lambda1, tMinusD), T(-2, t.Y))
	c.assertLadderOutputDistinct(lambda1, mu)
	// 4. Form the lazy result, whose curve membership comes from the final target.
	eta := fp.Add(lambda1, mu)
	x3 := fp.Lazy(T(1, eta, eta), T(-1, lambda1, lambda1), T(1, t.X))
	y3 := fp.Lazy(T(1, eta, fp.Sub(x3, xD)), T(1, yChord), T(-1, t.Y))
	return &point{X: x3, Y: y3}
}

// guardedAdd proves distinct X coordinates before applying affine addition.
// Inputs must already be on the curve with reduced, bounded coordinates.
func (c *curve) guardedAdd(p, q *point) *point {
	// Check the denominator before applying the ordinary affine equations.
	c.assertDistinctX(p.X, q.X)
	return c.add(p, q)
}

// scalarMulChecked handles the only excluded scalar class in the clamped
// quotient interval, s=1/3 modulo the selected subgroup order. It routes that
// case through [1/6](2Q)=[1/3]Q. Q must be a nonidentity prime-subgroup point
// and s must lie in [2^251,2^252), making the native comparison unambiguous.
func (c *curve) scalarMulChecked(q *point, s *frElement) *point {
	// 1. Detect s=1/3 in the selected prime subgroup within the clamped interval.
	native := c.nativeValue(s)
	third0 := new(big.Int).ModInverse(big.NewInt(3), order(false))
	third1 := new(big.Int).ModInverse(big.NewInt(3), order(true))
	selected := c.api.Select(c.twist, third1, third0)
	exceptional := c.api.IsZero(c.api.Sub(native, selected))
	// 2. Use (2Q,1/6) for that exception and (Q,s) otherwise.
	sixth0 := new(big.Int).ModInverse(big.NewInt(6), order(false))
	sixth1 := new(big.Int).ModInverse(big.NewInt(6), order(true))
	half := c.fp.Select(c.twist, c.fp.Const(sixth1), c.fp.Const(sixth0))
	return c.scalarMulLadder(c.selectPoint(exceptional, c.double(q), q), c.fp.Select(exceptional, half, s))
}

// scalarMulLadder proves R=[s]Q using bounded rational reconstruction and a
// joint radix-four ladder. Q must be a nonidentity prime-subgroup point and
// s must avoid 0, +/-1, +/-3, +/-1/3 modulo its order. scalarMulChecked
// ensures this for clamped quotients. The hinted R is independently checked
// on the curve and in the subgroup. A nonzero bounded reconstruction
// denominator and the final target equality bind R uniquely to [s]Q.
func (c *curve) scalarMulLadder(q *point, s *frElement) *point {
	// 1. Obtain and bound signed reconstruction halves from an untrusted hint.
	fr, fp, api := c.fr, c.fp, c.api
	decomposition, err := api.Compiler().NewHint(shortDecomposeScalarHint, 1+2*halfScalarBits, append([]frontend.Variable{c.twist}, c.limbHintInputs(s.Limbs())...)...)
	if err != nil {
		panic(fmt.Sprintf("decompose hint: %v", err))
	}
	sign := decomposition[0]
	api.AssertIsBoolean(sign)
	s1bits := decomposition[1 : 1+halfScalarBits]
	s2bits := decomposition[1+halfScalarBits:]
	var s1, s2 *frElement
	var s1digits, s2digits []frontend.Variable
	var s1Top, s2Top frontend.Variable
	if c.lay.Lookups {
		// Bits above bit 0 are consumed only through their radix-four digit.
		// Bounding the digit is sufficient. The constituent hint values need
		// not themselves be Boolean. Keep the hint's existing output shape.
		s1digits = c.radixFourDigits(s1bits)
		s2digits = c.radixFourDigits(s2bits)
		s1Top, s2Top = s1digits[len(s1digits)-1], s2digits[len(s2digits)-1]
		s1 = c.scalarFromRadixFour(s1bits[0], s1digits)
		s2 = c.scalarFromRadixFour(s2bits[0], s2digits)
		api.AssertIsDifferent(api.Add(s2bits[0], s2digits[0], s2digits[1:]...), 0)
	} else {
		for _, bits := range [][]frontend.Variable{s1bits, s2bits} {
			api.AssertIsEqual(bits[halfScalarBits-1], 0)
			for _, b := range bits[:halfScalarBits-1] {
				api.AssertIsBoolean(b)
			}
		}
		s1 = c.scalarFromBits(s1bits[:halfScalarBits-1])
		s2 = c.scalarFromBits(s2bits[:halfScalarBits-1])
		s1Top, s2Top = s1bits[halfScalarBits-2], s2bits[halfScalarBits-2]
		api.AssertIsDifferent(api.Add(s2bits[0], s2bits[1], s2bits[2:]...), 0)
	}
	// 2. Enforce s*signed(s2)+s1=0 in the selected scalar field.
	c.scalarZero(T(1, s, fr.Select(sign, fr.Neg(s2), s2)), T(1, s1))

	// 3. Independently prove that the candidate result is on-curve and in the subgroup.
	hinted := fp.Hint(shortScalarMulHint, 2, []frontend.Variable{c.twist}, q.X, q.Y, s)
	r := &point{X: hinted[0], Y: hinted[1]}
	c.assertOnCurve(r)
	c.assertSubgroup(r)

	// 4. Build the joint table, excluding every equal-X affine addition.
	q3 := c.triple(q)
	rSigned := &point{X: r.X, Y: fp.Select(sign, fp.Neg(r.Y), r.Y)}
	r3 := c.triple(rSigned)
	// Nonidentity prime-order R has 3R != ±R because its order exceeds four.
	r4 := c.add(r3, rSigned)
	c.assertDistinctX(r.X, q.X)
	c.assertDistinctX(r.X, q3.X)
	c.assertDistinctX(r3.X, q.X)
	negR := c.neg(rSigned)

	// 5. Prepare signed odd-multiple slots and the fixed leading accumulator.
	acc := c.add(q, rSigned)
	t1 := c.add(q3, r3)
	t2 := acc
	t3 := c.add(q3, rSigned)
	t4 := c.add(q, r3)
	t12 := c.add(negR, q)
	negR3 := c.neg(r3)
	slots := []*point{t1, c.add(q, negR3), c.add(q3, negR), t2, t4, c.add(q3, negR3), t12, t3}
	// Both subgroup orders give reconstructed halves strictly below 2^127.
	// Thus bit 127 is also zero and the leading folded step is Q+R.
	api.AssertIsEqual(s1Top, 0)
	api.AssertIsEqual(s2Top, 0)
	acc = t2
	lookup := func(i int) *point {
		return c.muxSlot(slots, s1bits[i], s2bits[i], s1bits[i-1], s2bits[i-1])
	}
	if c.lay.Lookups {
		lookup = c.packedTableLookup(slots, s1digits, s2digits)
	}
	// 6. Process each radix-four digit with the guarded lazy step.
	// Certain scalar residues can make an intermediate accumulator the identity.
	// This affine step then rejects an honest proof. A caller can retry with a
	// fresh scalar. The guards and final equality still bind every accepted R.
	for i := halfScalarBits - 3; i > 2; i -= 2 {
		acc = c.quadrupleAndAddLazy(acc, lookup(i))
	}
	acc = c.quadrupleAndAddLazy(acc, c.guardedAdd(lookup(2), r3))
	// 7. Both low bits zero would certify s1*Q+(s2+1)*R_signed=0 instead of
	// the intended relation. Require an odd half to bind the claimed R to s.
	// Equality to the known on-curve target also closes the backwards proof.
	api.AssertIsDifferent(api.Add(s1bits[0], s2bits[0]), 0)
	target := c.selectPoint(s1bits[0], c.selectPoint(s2bits[0], r3, r4), t4)
	c.assertEqual(acc, target)
	return r
}

// scalarFromBits packs Boolean scalar bits into bounded limbs. FromBinary
// constrains the bits, so the recorded limb widths follow from recomposition.
func (c *curve) scalarFromBits(bits []frontend.Variable) *frElement {
	var limbs []frontend.Variable
	var widths []int
	// Pack bounded binary chunks and record their exact widths.
	for i := 0; i < len(bits); i += c.lay.LimbBits {
		chunk := bits[i:min(len(bits), i+c.lay.LimbBits)]
		limbs = append(limbs, c.api.FromBinary(chunk...))
		widths = append(widths, len(chunk))
	}
	return c.fr.Bounded(limbs, widths)
}

// radixFourDigits bounds the reconstruction's low bit and paired radix-four
// digits. Other individual hint values need not be Boolean because only
// their bounded pairs are consumed. The final digit is restricted to one bit.
func (c *curve) radixFourDigits(bits []frontend.Variable) []frontend.Variable {
	// 1. Constrain the low bit used separately by the parity correction.
	c.api.AssertIsBoolean(bits[0])
	// 2. Bound each consumed pair as a digit, including the narrower top digit.
	digits := make([]frontend.Variable, (len(bits)-1)/2)
	for i := range digits {
		digits[i] = c.api.Add(bits[1+2*i], c.api.Mul(bits[2+2*i], 2))
		width := 2
		if i == len(digits)-1 {
			width = 1
		}
		c.rangeChecker().Check(digits[i], width)
	}
	return digits
}

// scalarFromRadixFour packs an already bounded low bit and radix-four digits.
// It splits only digits crossing a limb boundary, preserving exact integer
// recomposition. The final digit must have the one-bit bound from radixFourDigits.
func (c *curve) scalarFromRadixFour(low frontend.Variable, digits []frontend.Variable) *frElement {
	// 1. Describe the existing low-bit, digit and top-digit bounds.
	values := append([]frontend.Variable{low}, digits...)
	widths := make([]int, len(values))
	widths[0] = 1
	for i := 1; i < len(widths); i++ {
		widths[i] = 2
	}
	widths[len(widths)-1] = 1
	var limbs []frontend.Variable
	var limbWidths []int
	var limb frontend.Variable = 0
	used := 0
	// 2. Pack exact limbs, decomposing only a digit that crosses a boundary.
	for i, v := range values {
		width := widths[i]
		available := c.lay.LimbBits - used
		if width > available {
			// Only the radix-four digit straddling an odd limb boundary needs bits.
			split := c.api.ToBinary(v, width)
			limb = c.api.Add(limb, c.api.Mul(c.api.FromBinary(split[:available]...), pow2(used)))
			limbs = append(limbs, limb)
			limbWidths = append(limbWidths, c.lay.LimbBits)
			limb = c.api.FromBinary(split[available:]...)
			used = width - available
		} else {
			limb = c.api.Add(limb, c.api.Mul(v, pow2(used)))
			used += width
			if used == c.lay.LimbBits {
				limbs = append(limbs, limb)
				limbWidths = append(limbWidths, used)
				limb = 0
				used = 0
			}
		}
	}
	// 3. Retain the partial top limb with its established width.
	if used > 0 {
		limbs = append(limbs, limb)
		limbWidths = append(limbWidths, used)
	}
	return c.fr.Bounded(limbs, limbWidths)
}

// shortDecomposeScalarHint proposes signed rational-reconstruction halves.
// scalarMulLadder checks their bounds, congruence, nonzero denominator and
// parity condition. No soundness assumption depends on this host algorithm.
func shortDecomposeScalarHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	// 1. Check the output shape and reconstruct the scalar for the selected order.
	if len(outputs) != 1+2*halfScalarBits {
		return errors.New("expecting the sign and bit outputs")
	}
	s := limbHintValue(inputs[1:])
	n := order(inputs[0].Sign() != 0)
	// 2. Compute rational reconstruction and normalize the numerator sign.
	res := lattice.NewReconstructor(n).RationalReconstruct(s.Mod(s, n))
	x, z := new(big.Int).Set(res[0]), new(big.Int).Set(res[1])
	if x.Sign() < 0 {
		x.Neg(x)
		z.Neg(z)
	}
	// 3. Emit the sign and magnitudes for independent circuit checks.
	outputs[0].SetUint64(0)
	if z.Sign() > 0 {
		outputs[0].SetUint64(1)
	}
	z.Abs(z)
	for i := 0; i < halfScalarBits; i++ {
		outputs[1+i].SetUint64(uint64(x.Bit(i)))
		outputs[1+halfScalarBits+i].SetUint64(uint64(z.Bit(i)))
	}
	return nil
}

// shortScalarMulHint proposes R=[s]Q on the selected curve. scalarMulLadder
// checks the output's membership and multiplication relation independently.
// The variable-time host multiplication is witness generation, not encryption.
func shortScalarMulHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, n, in, out []*big.Int) error {
		// 1. Check the hint shape.
		if len(n) != 1 || len(in) != 3 || len(out) != 2 {
			return errors.New("scalar mul shape")
		}
		// 2. Compute the candidate product and reject infinity for honest witnesses.
		a, _ := coefficients(n[0].Sign() != 0)
		r := hostMul(hostPoint{in[0], in[1]}, in[2], a)
		if r.x == nil {
			return errors.New("scalar mul infinity")
		}
		// 3. Return candidate coordinates for membership and ladder verification.
		out[0].Set(r.x)
		out[1].Set(r.y)
		return nil
	})
}

// implicitDoubledY computes a host Y coordinate from a proposed tangent.
// It is used only to generate hints. The ladder equations supply the proof.
func implicitDoubledY(p *big.Int, lambda0, xA, xD, yA *big.Int) *big.Int {
	y := new(big.Int).Sub(xA, xD)
	y.Mul(y, lambda0).Sub(y, yA)
	return y.Mod(y, p)
}

// modRatio computes a variable-time host quotient modulo a public prime.
// It returns zero for a zero denominator to allow witness generation at
// exceptional inputs. Callers must constrain denominators or resolve those
// cases through the ladder proof. This helper supplies no security check.
func modRatio(p, num, den *big.Int) *big.Int {
	// 1. Reduce the denominator and handle zero for witness generation.
	d := new(big.Int).Mod(den, p)
	if d.Sign() == 0 {
		return new(big.Int)
	}
	// 2. Compute the host inverse and reduce the resulting quotient.
	d.ModInverse(d, p)
	return d.Mul(d, num).Mod(d, p)
}

// shortImplicitChordHint proposes the chord from 2A to T, or its tangent
// when those points coincide. The hint is untrusted. The lazy step's equations,
// output guard and final target equality jointly validate the equal-point case.
func shortImplicitChordHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		// 1. Check the hint shape.
		if len(in) != 7 || len(out) != 1 {
			return errors.New("expecting seven inputs and one output")
		}
		// 2. Recover the implicit doubled point and distinguish tangent from chord.
		yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
		dx := new(big.Int).Sub(in[4], in[2])
		dy := new(big.Int).Sub(in[5], yD)
		if new(big.Int).Mod(dx, p).Sign() == 0 && new(big.Int).Mod(dy, p).Sign() == 0 {
			// Equality to the known on-curve final target pins this tangent.
			num := new(big.Int).Mul(in[2], in[2])
			num.Mul(num, big.NewInt(3)).Add(num, in[6])
			out[0].Set(modRatio(p, num, new(big.Int).Lsh(yD, 1)))
			return nil
		}
		out[0].Set(modRatio(p, dy, dx))
		return nil
	})
}

// shortImplicitSecondSlopeHint proposes the second lazy-step slope correction.
// Its denominator-cleared relation and the global ladder proof constrain it.
// The host quotient is not itself evidence that the denominator is nonzero.
func shortImplicitSecondSlopeHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		// 1. Check the hint shape.
		if len(in) != 5 || len(out) != 1 {
			return errors.New("expecting five inputs and one output")
		}
		// 2. Propose the correction 2*yD/(x2-xD) for the constrained relation.
		yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
		out[0].Set(modRatio(p, yD.Lsh(yD, 1), new(big.Int).Sub(in[4], in[2])))
		return nil
	})
}

// packedCoordinate combines already bounded limbs into native-field groups.
// The caller selects a group width below the native modulus. Signed Y groups
// are kept small enough for subsequent products and tracked as signed bounds.
func (c *curve) packedCoordinate(e *fpElement, group int) []frontend.Variable {
	api := c.api
	limbs := e.Limbs()
	var out []frontend.Variable
	// Recompose each group using the caller's established limb bounds.
	for g := 0; g < len(limbs); g += group {
		sum := frontend.Variable(0)
		for j := g; j < min(g+group, len(limbs)); j++ {
			sum = api.Add(sum, api.Mul(limbs[j], pow2(c.lay.LimbBits*(j-g))))
		}
		out = append(out, sum)
	}
	return out
}

// unpackedCoordinate records packed groups as sparse emulated limbs.
// The inputs must come from a checked lookup or Boolean selection of bounded
// rows. WithBounds records that justification and adds no range constraints.
func (c *curve) unpackedCoordinate(packed []frontend.Variable, group int, signed bool) *fpElement {
	// 1. Derive each packed group's unsigned or signed interval.
	widths := c.fp.ReducedWidths()
	n := len(widths)
	limbs := make([]frontend.Variable, n)
	lo, hi := make([]*big.Int, n), make([]*big.Int, n)
	for j := range limbs {
		limbs[j] = 0
		lo[j], hi[j] = new(big.Int), new(big.Int)
		if j%group != 0 {
			continue
		}
		bits := 0
		for _, w := range widths[j:min(j+group, n)] {
			bits += w
		}
		limbs[j] = packed[j/group]
		hi[j].Sub(pow2(bits), big.NewInt(1))
		if signed {
			lo[j].Neg(hi[j])
		}
	}
	// 2. Record the bounds justified by the checked selection, without new hints.
	return c.fp.WithBounds(limbs, lo, hi)
}

// packedTableLookup creates a checked lookup over the 16 signed ladder slots.
// Slots must have proven curve membership and reduced coordinate bounds.
// The committed row lookup binds the selector and every output column,
// justifying the bounds assigned when unpacking the selected coordinates.
func (c *curve) packedTableLookup(slots []*point, s1digits, s2digits []frontend.Variable) func(i int) *point {
	// 1. Size the packed coordinate columns using their established limb bounds.
	api, fp := c.api, c.fp
	widths := fp.ReducedWidths()
	nbLimbs := len(widths)
	nbPackedX := (nbLimbs + packedXGroup - 1) / packedXGroup
	nbPackedY := (nbLimbs + c.packedYGroup() - 1) / c.packedYGroup()
	table := lookup.New(api, nbPackedX+nbPackedY)
	// 2. Insert all signed slots with the selector's exact radix-four ordering.
	for idx := 0; idx < 16; idx++ {
		// The radix-four selector lists each scalar's low bit first. The
		// joint ladder's slot ordering lists the high bits first instead.
		bitIndex := (idx>>1)&1 | ((idx>>3)&1)<<1 | (idx&1)<<2 | ((idx>>2)&1)<<3
		sx := bitIndex
		if bitIndex >= 8 {
			sx = 15 - bitIndex
		}
		slot := slots[sx]
		if !slot.X.IsReduced(widths) || !slot.Y.IsReduced(widths) {
			panic("table points must be reduced")
		}
		y := slot.Y
		if bitIndex&1 == 0 {
			y = fp.Neg(y)
		}
		row := append(c.packedCoordinate(slot.X, packedXGroup), c.packedCoordinate(y, c.packedYGroup())...)
		table.Insert(row)
	}
	// 3. Bind each query to a committed row and recover bounded coordinates.
	return func(i int) *point {
		digit := (i - 2) / 2
		selector := api.Add(s1digits[digit], api.Mul(s2digits[digit], 4))
		cols := table.Lookup(selector)
		x := c.unpackedCoordinate(cols[:nbPackedX], packedXGroup, false)
		if i == 2 {
			// The final guarded addition compares reduced X coordinates.
			x = fp.Eval(T(1, x))
		}
		return &point{X: x, Y: c.unpackedCoordinate(cols[nbPackedX:nbPackedX+nbPackedY], c.packedYGroup(), true)}
	}
}

// muxSlot selects the same signed ladder slot without lookup arguments.
// The selector inputs must be Boolean, and all eight slots must already have
// curve membership and reduced bounds. Coordinate selection preserves both.
func (c *curve) muxSlot(slots []*point, b0, b1, b2, b3 frontend.Variable) *point {
	// 1. Require reduced coordinate bounds for every candidate slot.
	api, fp := c.api, c.fp
	widths := fp.ReducedWidths()
	for _, slot := range slots {
		if !slot.X.IsReduced(widths) || !slot.Y.IsReduced(widths) {
			panic("table points must be reduced")
		}
	}
	// 2. Select the slot through Boolean multiplexers.
	sel := []frontend.Variable{api.Xor(b0, b3), api.Xor(b1, b3), api.Xor(b2, b3)}
	mux := func(column func(int) []frontend.Variable) []frontend.Variable {
		level := make([][]frontend.Variable, len(slots))
		for i := range slots {
			level[i] = column(i)
		}
		for _, bit := range sel {
			next := make([][]frontend.Variable, len(level)/2)
			for j := range next {
				next[j] = make([]frontend.Variable, len(level[2*j]))
				for l := range next[j] {
					next[j][l] = api.Select(bit, level[2*j+1][l], level[2*j][l])
				}
			}
			level = next
		}
		return level[0]
	}
	// 3. Restore the selected Y sign and retain the proven coordinate bounds.
	xs := mux(func(i int) []frontend.Variable { return slots[i].X.Limbs() })
	packed := mux(func(i int) []frontend.Variable { return c.packedCoordinate(slots[i].Y, c.packedYGroup()) })
	sign := api.Sub(api.Mul(b0, 2), 1)
	for g := range packed {
		packed[g] = api.Mul(sign, packed[g])
	}
	return &point{X: fp.Reduced(xs), Y: c.unpackedCoordinate(packed, c.packedYGroup(), true)}
}

// packedYGroup keeps each packed Y below half the native-field width.
// This prevents native wraparound in the subsequent squared differences.
func (c *curve) packedYGroup() int { return min(3, 120/c.lay.LimbBits) }
