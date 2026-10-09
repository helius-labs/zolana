// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
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

package emfield

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

const maxFoldDigit = 16

type productKey struct {
	a, b  *Element
	point int
}

type arithmeticState struct {
	foldDigits      []*big.Int
	foldRows        [][]*big.Int
	inverseMatrices map[int][][]*big.Int
	products        map[productKey]frontend.Variable
	crt             *crtBasis
	crtDone         bool
	crtProducts     map[productKey]frontend.Variable
}

type linForm struct {
	vars   []frontend.Variable
	coefs  []*big.Int
	consts *big.Int
}

type Term struct {
	Coef    int64
	Factors []*Element
}

type term struct {
	coef    *big.Int
	factors []*Element
}

func T(coef int64, factors ...*Element) Term {
	return Term{Coef: coef, Factors: factors}
}

func (f *Field) Eval(terms ...Term) *Element {
	return f.checkPolynomial(terms, true)
}

func (f *Field) AssertZero(terms ...Term) {
	f.checkPolynomial(terms, false)
}

func (f *Field) checkPolynomial(inputTerms []Term, withResult bool) *Element {
	api, layout := f.api, f.layout
	nativeModulus := api.Compiler().Field()
	halfNativeModulus := new(big.Int).Rsh(nativeModulus, 1)
	limbCount, limbBits := layout.NbLimbs, layout.LimbBits

	// 1. Collect terms and bound their polynomial coefficients and integer sum.
	terms := make([]term, len(inputTerms))
	var elements []*Element
	elementIndices := map[*Element]int{}
	for i, t := range inputTerms {
		terms[i] = term{coef: big.NewInt(t.Coef), factors: t.Factors}
		for _, e := range t.Factors {
			if _, ok := elementIndices[e]; !ok {
				elementIndices[e] = len(elements)
				elements = append(elements, e)
			}
		}
	}

	var coefficientBounds []*big.Int
	expressionMin, expressionMax := new(big.Int), new(big.Int)
	for _, t := range terms {
		poly := []*big.Int{new(big.Int).Abs(t.coef)}
		for _, e := range t.factors {
			poly = polyMulAbs(poly, limbAbs(e))
		}
		coefficientBounds = addInto(coefficientBounds, poly)
		lo, hi := termRange(t)
		expressionMin.Add(expressionMin, lo)
		expressionMax.Add(expressionMax, hi)
	}
	for _, c := range coefficientBounds {
		if c.Cmp(halfNativeModulus) >= 0 {
			panic("product coefficient does not fit the native field")
		}
	}
	degree := len(coefficientBounds) - 1

	// 2. Fold high coefficients using the modulus shape when supported.
	fold := f.arithmetic.fold(limbCount, degree)
	positions := len(coefficientBounds)
	foldedBounds := coefficientBounds
	foldedMin, foldedMax := expressionMin, expressionMax
	if fold != nil {
		positions = limbCount
		foldedBounds = make([]*big.Int, limbCount)
		for j := range foldedBounds {
			foldedBounds[j] = new(big.Int)
			for i, c := range coefficientBounds {
				foldedBounds[j].Add(foldedBounds[j], new(big.Int).Mul(new(big.Int).Abs(fold[i][j]), c))
			}
			if foldedBounds[j].Cmp(halfNativeModulus) >= 0 {
				panic("folded coefficient does not fit the native field")
			}
		}
		total := new(big.Int)
		for j, c := range foldedBounds {
			total.Add(total, new(big.Int).Lsh(c, uint(limbBits*j)))
		}
		foldedMin, foldedMax = new(big.Int).Neg(total), total
	}

	// 3. Bound the remainder and shifted quotient needed for the modular relation.
	remainderMax := new(big.Int)
	if withResult {
		remainderMax.Sub(pow2(f.modulusBits), big.NewInt(1))
	}
	quotientMin := floorDiv(new(big.Int).Sub(foldedMin, remainderMax), f.mod)
	quotientMax := floorDiv(foldedMax, f.mod)
	offset := new(big.Int)
	if quotientMin.Sign() < 0 {
		offset.Neg(quotientMin)
	}
	quotientBits := max(new(big.Int).Add(quotientMax, offset).BitLen(), 1)
	var quotientWidths []int
	if fold != nil {
		quotientWidths = []int{quotientBits}
	} else {
		quotientWidths = layout.splitWidths(quotientBits)
	}
	offsetLimbs := make([]*big.Int, len(quotientWidths))
	remainingOffset := new(big.Int).Set(offset)
	for i, w := range quotientWidths {
		offsetLimbs[i] = new(big.Int).And(remainingOffset, new(big.Int).Sub(pow2(w), big.NewInt(1)))
		remainingOffset.Rsh(remainingOffset, uint(w))
	}
	quotientBounds := make([]*big.Int, len(quotientWidths))
	for i, w := range quotientWidths {
		quotientBounds[i] = maxInt(offsetLimbs[i], new(big.Int).Sub(new(big.Int).Sub(pow2(w), big.NewInt(1)), offsetLimbs[i]))
	}

	// 4. Bound the residual expression and choose how many carry positions to check.
	residualBounds := append([]*big.Int{}, foldedBounds...)
	for i := range residualBounds {
		residualBounds[i] = new(big.Int).Set(residualBounds[i])
	}
	if withResult {
		rAbs := make([]*big.Int, len(f.widths))
		for i, w := range f.widths {
			rAbs[i] = new(big.Int).Sub(pow2(w), big.NewInt(1))
		}
		residualBounds = addInto(residualBounds, rAbs)
	}
	if len(quotientBounds) > 0 {
		residualBounds = addInto(residualBounds, polyMulAbs(quotientBounds, f.modulusLimbs))
	}
	positions = max(positions, len(residualBounds))
	for len(residualBounds) < positions {
		residualBounds = append(residualBounds, new(big.Int))
	}
	quotientMagnitude := maxInt(offset, new(big.Int).Sub(new(big.Int).Sub(pow2(quotientBits), big.NewInt(1)), offset))
	residualMagnitude := absMax(foldedMin, foldedMax)
	residualMagnitude.Add(residualMagnitude, remainderMax).Add(residualMagnitude, new(big.Int).Mul(quotientMagnitude, f.mod))
	carryPositions := 0
	for carryPositions < positions-1 && new(big.Int).Lsh(nativeModulus, uint(limbBits*carryPositions)).Cmp(residualMagnitude) <= 0 {
		carryPositions++
	}
	checkTopCoefficient := new(big.Int).Lsh(nativeModulus, uint(limbBits*carryPositions)).Cmp(residualMagnitude) <= 0

	// 5. Hint and range-check the remainder and, when needed, quotient limbs.
	var remainder *Element
	var quotientLimbs []frontend.Variable
	outputCount := 0
	if withResult {
		outputCount += layout.nbPiecesAll(f.widths)
	}
	if fold == nil {
		outputCount += layout.nbPiecesAll(quotientWidths)
	}
	if outputCount > 0 {
		inputs := layout.header()
		for _, l := range f.modulusLimbs {
			inputs = append(inputs, l)
		}
		hasRemainder, hasQuotient := 0, 0
		if withResult {
			hasRemainder = 1
		}
		if fold == nil {
			hasQuotient = 1
		}
		inputs = append(inputs, hasRemainder, hasQuotient, quotientBits)
		for _, o := range offsetLimbs {
			inputs = append(inputs, o)
		}
		inputs = append(inputs, len(terms))
		for _, t := range terms {
			inputs = append(inputs, t.coef, len(t.factors))
			for _, e := range t.factors {
				inputs = append(inputs, elementIndices[e])
			}
		}
		inputs = append(inputs, len(elements))
		for _, e := range elements {
			inputs = append(inputs, len(e.limbs))
			inputs = append(inputs, e.limbs...)
		}
		out, err := api.Compiler().NewHint(PlainCheckHint, outputCount, inputs...)
		if err != nil {
			panic(fmt.Sprintf("plain check hint: %v", err))
		}
		if withResult {
			remainder, out = f.fromPieces(out, f.widths)
		}
		if fold == nil {
			var k *Element
			k, _ = f.fromPieces(out, quotientWidths)
			quotientLimbs = k.limbs
		}
	}

	// 6. Build the polynomial relation; derive a folded quotient in the native field.
	expressionForm := f.foldedForms(terms, degree, fold)

	var quotientExpression frontend.Variable
	if fold != nil {
		native := newLinForm()
		for j := 0; j < limbCount; j++ {
			mergeForm(native, expressionForm(j), pow2(limbBits*j))
		}
		if withResult {
			for j, l := range remainder.limbs {
				native.add(l, new(big.Int).Neg(pow2(limbBits*j)))
			}
		}
		inv := new(big.Int).ModInverse(f.mod, nativeModulus)
		k := native.build(api)
		quotientExpression = api.Mul(k, inv)
		f.rc.Check(api.Add(quotientExpression, offset), quotientBits)
	}

	residualForm := func(pos int) *linForm {
		form := expressionForm(pos)
		if withResult && pos < len(remainder.limbs) {
			form.add(remainder.limbs[pos], big.NewInt(-1))
		}
		if fold != nil {
			if pos < len(f.modulusLimbs) {
				form.add(quotientExpression, new(big.Int).Neg(f.modulusLimbs[pos]))
			}
		} else {
			for a, kl := range quotientLimbs {
				modulusIndex := pos - a
				if modulusIndex < 0 || modulusIndex >= len(f.modulusLimbs) {
					continue
				}
				form.add(kl, new(big.Int).Neg(f.modulusLimbs[modulusIndex]))
				form.addConst(new(big.Int).Mul(offsetLimbs[a], f.modulusLimbs[modulusIndex]))
			}
		}
		return form
	}

	if fold == nil && !checkTopCoefficient {
		native := newLinForm()
		for pos := 0; pos < positions; pos++ {
			mergeForm(native, residualForm(pos), pow2(limbBits*pos))
		}
		api.AssertIsEqual(native.build(api), 0)
	}

	// 7. Check bounded carries and the final coefficient to prove the integer relation.
	var carry frontend.Variable = 0
	previousCarryBits := -1
	for pos := 0; pos < carryPositions; {
		start := pos
		groupBound := new(big.Int)
		if previousCarryBits >= 0 {
			groupBound.Set(pow2(previousCarryBits))
		}
		carryBits := 0
		for pos < carryPositions {
			shift := limbBits * (pos + 1 - start)
			candidateBound := new(big.Int).Add(groupBound, new(big.Int).Lsh(residualBounds[pos], uint(limbBits*(pos-start))))
			candidateCarryBits := new(big.Int).Rsh(candidateBound, uint(shift)).BitLen()
			lift := new(big.Int).Add(candidateBound, new(big.Int).Lsh(big.NewInt(1), uint(shift+candidateCarryBits)))
			if lift.Cmp(halfNativeModulus) >= 0 {
				break
			}
			groupBound, carryBits = candidateBound, candidateCarryBits
			pos++
		}
		if pos == start {
			panic(fmt.Sprintf("carry %d does not lift", start))
		}
		group := newLinForm()
		for p := start; p < pos; p++ {
			mergeForm(group, residualForm(p), pow2(limbBits*(p-start)))
		}
		sum := api.Add(group.build(api), carry)
		carry = api.Mul(sum, new(big.Int).ModInverse(pow2(limbBits*(pos-start)), nativeModulus))
		f.rc.Check(api.Add(carry, pow2(carryBits)), carryBits+1)
		previousCarryBits = carryBits
	}
	if checkTopCoefficient {
		top := residualForm(carryPositions).build(api)
		if new(big.Int).Add(residualBounds[carryPositions], pow2(previousCarryBits)).Cmp(halfNativeModulus) >= 0 {
			panic("top coefficient does not lift")
		}
		api.AssertIsEqual(api.Add(top, carry), 0)
	}
	return remainder
}

func (f *Field) Lazy(inputTerms ...Term) *Element {
	if f.arithmetic == nil || f.arithmetic.foldDigits == nil {
		panic("lazy elements need the folded plain layout")
	}
	limbCount, limbBits := f.layout.NbLimbs, f.layout.LimbBits
	halfNativeModulus := new(big.Int).Rsh(f.api.Compiler().Field(), 1)
	terms := make([]term, len(inputTerms))
	var coefficientMin, coefficientMax []*big.Int
	for i, t := range inputTerms {
		terms[i] = term{coef: big.NewInt(t.Coef), factors: t.Factors}
		lo, hi := []*big.Int{big.NewInt(t.Coef)}, []*big.Int{big.NewInt(t.Coef)}
		for _, e := range t.Factors {
			lo, hi = polyMulInterval(lo, hi, e.lo, e.hi)
		}
		coefficientMin, coefficientMax = addInto(coefficientMin, lo), addInto(coefficientMax, hi)
	}
	for i := range coefficientMin {
		if absMax(coefficientMin[i], coefficientMax[i]).Cmp(halfNativeModulus) >= 0 {
			panic("lazy coefficient does not fit the native field")
		}
	}
	degree := len(coefficientMin) - 1
	fold := f.arithmetic.fold(limbCount, degree)
	expressionForm := f.foldedForms(terms, degree, fold)
	e := &Element{limbs: make([]frontend.Variable, limbCount), lo: make([]*big.Int, limbCount), hi: make([]*big.Int, limbCount), valueMin: new(big.Int), valueMax: new(big.Int)}
	for j := 0; j < limbCount; j++ {
		lo, hi := new(big.Int), new(big.Int)
		for i := range coefficientMin {
			c := fold[i][j]
			switch c.Sign() {
			case 1:
				lo.Add(lo, new(big.Int).Mul(c, coefficientMin[i]))
				hi.Add(hi, new(big.Int).Mul(c, coefficientMax[i]))
			case -1:
				lo.Add(lo, new(big.Int).Mul(c, coefficientMax[i]))
				hi.Add(hi, new(big.Int).Mul(c, coefficientMin[i]))
			}
		}
		if absMax(lo, hi).Cmp(halfNativeModulus) >= 0 {
			panic("lazy limb does not fit the native field")
		}
		e.limbs[j] = expressionForm(j).build(f.api)
		e.lo[j], e.hi[j] = lo, hi
		e.valueMin.Add(e.valueMin, new(big.Int).Lsh(lo, uint(limbBits*j)))
		e.valueMax.Add(e.valueMax, new(big.Int).Lsh(hi, uint(limbBits*j)))
	}
	return e
}

func (f *Field) HintBalanced(fn solver.Hint, nbOutputs int, natives []frontend.Variable, elems ...*Element) []*Element {
	api := f.api
	limbCount := len(f.widths)
	piecesPerElement := f.layout.nbPiecesAll(f.widths)
	raw, err := api.Compiler().NewHint(fn, nbOutputs*piecesPerElement, f.hintInputs(natives, elems)...)
	if err != nil {
		panic(fmt.Sprintf("field hint: %v", err))
	}
	inputs := f.layout.header()
	for _, l := range f.modulusLimbs {
		inputs = append(inputs, l)
	}
	pieces, err := api.Compiler().NewHint(BalanceHint, nbOutputs*piecesPerElement, append(inputs, raw...)...)
	if err != nil {
		panic(fmt.Sprintf("balance hint: %v", err))
	}
	elements := make([]*Element, nbOutputs)
	for i := range elements {
		limbs := make([]frontend.Variable, limbCount)
		lowerBounds, upperBounds := make([]*big.Int, limbCount), make([]*big.Int, limbCount)
		remainingPieces := pieces[i*piecesPerElement : (i+1)*piecesPerElement]
		for j, w := range f.widths {
			pieceCount := f.layout.nbPieces(w)
			unsignedLimb := f.rc.Compose(remainingPieces[:pieceCount], w)
			remainingPieces = remainingPieces[pieceCount:]
			limbs[j] = api.Sub(unsignedLimb, pow2(w-1))
			lowerBounds[j] = new(big.Int).Neg(pow2(w - 1))
			upperBounds[j] = new(big.Int).Sub(pow2(w-1), big.NewInt(1))
		}
		elements[i] = f.WithBounds(limbs, lowerBounds, upperBounds)
	}
	return elements
}

func newArithmeticState(f *Field) *arithmeticState {
	s := &arithmeticState{inverseMatrices: map[int][][]*big.Int{}, products: map[productKey]frontend.Variable{}, crtProducts: map[productKey]frontend.Variable{}}
	l := f.layout
	top := new(big.Int).Mod(pow2(l.LimbBits*l.NbLimbs), f.mod)
	digits := balancedDigits(top, l.LimbBits, l.NbLimbs)
	if digits == nil {
		return s
	}
	for _, d := range digits {
		if new(big.Int).Abs(d).Cmp(big.NewInt(maxFoldDigit)) > 0 {
			return s
		}
	}
	s.foldDigits = digits
	return s
}

func (s *arithmeticState) fold(n, degree int) [][]*big.Int {
	if s.foldDigits == nil {
		return nil
	}
	for len(s.foldRows) <= degree {
		i := len(s.foldRows)
		row := make([]*big.Int, n)
		for j := range row {
			row[j] = new(big.Int)
		}
		if i < n {
			row[i].SetInt64(1)
		} else {
			prev := s.foldRows[i-1]
			for j := 1; j < n; j++ {
				row[j].Set(prev[j-1])
			}
			carry := prev[n-1]
			for j := range row {
				row[j].Add(row[j], new(big.Int).Mul(carry, s.foldDigits[j]))
			}
		}
		s.foldRows = append(s.foldRows, row)
	}
	return s.foldRows[:degree+1]
}

func (f *Field) foldedForms(terms []term, degree int, fold [][]*big.Int) func(j int) *linForm {
	q := f.api.Compiler().Field()
	n := f.layout.NbLimbs
	var crt *crtBasis
	if fold != nil {
		crt = f.arithmetic.crtBasis(f, q)
	}
	coefForms := make([]*linForm, degree+1)
	for i := range coefForms {
		coefForms[i] = newLinForm()
	}
	var crtForms []*linForm
	for _, t := range terms {
		switch len(t.factors) {
		case 0:
			coefForms[0].addConst(t.coef)
			continue
		case 1:
			for i, l := range t.factors[0].limbs {
				coefForms[i].add(l, t.coef)
			}
			continue
		}
		if crt != nil && len(t.factors) == 2 && len(t.factors[0].limbs) == n && len(t.factors[1].limbs) == n {
			if crtForms == nil {
				crtForms = make([]*linForm, n)
				for j := range crtForms {
					crtForms[j] = newLinForm()
				}
			}
			for k := range crt.forms {
				w := f.crtProductAt(crt, t.factors[0], t.factors[1], k)
				for j, row := range crt.combine {
					crtForms[j].add(w, new(big.Int).Mul(t.coef, row[k]))
				}
			}
			continue
		}
		d := 0
		for _, e := range t.factors {
			d += elementDegree(e)
		}
		inverseMatrices := f.arithmetic.inverseVandermonde(d, q)
		for k := 0; k <= d; k++ {
			w := f.productAt(t.factors, k)
			for i := 0; i <= d; i++ {
				coefForms[i].add(w, new(big.Int).Mul(t.coef, inverseMatrices[i][k]))
			}
		}
	}
	return func(j int) *linForm {
		form := newLinForm()
		if fold == nil {
			if j < len(coefForms) {
				mergeForm(form, coefForms[j], big.NewInt(1))
			}
			return form
		}
		for i, cf := range coefForms {
			if fold[i][j].Sign() != 0 {
				mergeForm(form, cf, fold[i][j])
			}
		}
		if crtForms != nil {
			mergeForm(form, crtForms[j], big.NewInt(1))
		}
		return form
	}
}

func (f *Field) productAt(factors []*Element, k int) frontend.Variable {
	x := evalPoint(k)
	s := f.arithmetic
	var acc frontend.Variable
	rest := factors
	if len(factors) >= 2 {
		key := productKey{factors[0], factors[1], k}
		if v, ok := s.products[key]; ok {
			acc = v
		} else if v, ok := s.products[productKey{factors[1], factors[0], k}]; ok {
			acc = v
		} else {
			acc = f.api.Mul(f.evalAt(factors[0], x), f.evalAt(factors[1], x))
			s.products[key] = acc
		}
		rest = factors[2:]
	}
	for _, e := range rest {
		acc = f.api.Mul(acc, f.evalAt(e, x))
	}
	return acc
}

func (f *Field) crtProductAt(b *crtBasis, x, y *Element, k int) frontend.Variable {
	s := f.arithmetic
	if v, ok := s.crtProducts[productKey{x, y, k}]; ok {
		return v
	}
	if v, ok := s.crtProducts[productKey{y, x, k}]; ok {
		return v
	}
	eval := func(e *Element) frontend.Variable {
		form := newLinForm()
		for i, l := range e.limbs {
			form.add(l, b.forms[k][i])
		}
		return form.build(f.api)
	}
	v := f.api.Mul(eval(x), eval(y))
	s.crtProducts[productKey{x, y, k}] = v
	return v
}

func (f *Field) evalAt(e *Element, x int64) frontend.Variable {
	acc := frontend.Variable(0)
	pw := big.NewInt(1)
	for _, l := range e.limbs {
		acc = f.api.Add(acc, f.api.Mul(l, new(big.Int).Set(pw)))
		pw.Mul(pw, big.NewInt(x))
	}
	return acc
}

func balancedDigits(v *big.Int, bits, n int) []*big.Int {
	base := pow2(bits)
	half := pow2(bits - 1)
	rest := new(big.Int).Set(v)
	out := make([]*big.Int, 0, n)
	for len(out) < n {
		d := new(big.Int).Mod(rest, base)
		if d.Cmp(half) > 0 {
			d.Sub(d, base)
		}
		out = append(out, d)
		rest.Sub(rest, d).Rsh(rest, uint(bits))
	}
	if rest.Sign() != 0 {
		return nil
	}
	return out
}

func evalPoint(k int) int64 {
	if k == 0 {
		return 0
	}
	if k%2 == 1 {
		return int64((k + 1) / 2)
	}
	return -int64(k / 2)
}

func (s *arithmeticState) inverseVandermonde(degree int, nativeModulus *big.Int) [][]*big.Int {
	if m, ok := s.inverseMatrices[degree]; ok {
		return m
	}
	size := degree + 1
	matrix := make([][]*big.Int, size)
	for k := range matrix {
		matrix[k] = make([]*big.Int, 2*size)
		x := big.NewInt(evalPoint(k))
		power := big.NewInt(1)
		for i := 0; i < size; i++ {
			matrix[k][i] = new(big.Int).Mod(power, nativeModulus)
			power = new(big.Int).Mul(power, x)
		}
		for i := 0; i < size; i++ {
			matrix[k][size+i] = new(big.Int)
			if i == k {
				matrix[k][size+i].SetInt64(1)
			}
		}
	}
	for col := 0; col < size; col++ {
		pivot := -1
		for r := col; r < size; r++ {
			if matrix[r][col].Sign() != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			panic("singular evaluation points")
		}
		matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
		inv := new(big.Int).ModInverse(matrix[col][col], nativeModulus)
		for j := range matrix[col] {
			matrix[col][j].Mul(matrix[col][j], inv).Mod(matrix[col][j], nativeModulus)
		}
		for r := 0; r < size; r++ {
			if r == col || matrix[r][col].Sign() == 0 {
				continue
			}
			factor := new(big.Int).Set(matrix[r][col])
			for j := range matrix[r] {
				matrix[r][j].Sub(matrix[r][j], new(big.Int).Mul(factor, matrix[col][j])).Mod(matrix[r][j], nativeModulus)
			}
		}
	}
	inverse := make([][]*big.Int, size)
	for i := range inverse {
		inverse[i] = matrix[i][size:]
	}
	s.inverseMatrices[degree] = inverse
	return inverse
}

func newLinForm() *linForm {
	return &linForm{consts: new(big.Int)}
}

func (l *linForm) add(v frontend.Variable, c *big.Int) {
	if c.Sign() == 0 {
		return
	}
	l.vars = append(l.vars, v)
	l.coefs = append(l.coefs, new(big.Int).Set(c))
}

func (l *linForm) addConst(c *big.Int) {
	l.consts.Add(l.consts, c)
}

func (l *linForm) build(api frontend.API) frontend.Variable {
	q := api.Compiler().Field()
	acc := frontend.Variable(new(big.Int).Mod(l.consts, q))
	for i, v := range l.vars {
		acc = api.Add(acc, api.Mul(v, new(big.Int).Mod(l.coefs[i], q)))
	}
	return acc
}

func elementDegree(e *Element) int {
	return len(e.limbs) - 1
}

func mergeForm(destination, source *linForm, coefficient *big.Int) {
	for i, v := range source.vars {
		destination.add(v, new(big.Int).Mul(source.coefs[i], coefficient))
	}
	destination.addConst(new(big.Int).Mul(source.consts, coefficient))
}

func (s *arithmeticState) crtBasis(f *Field, q *big.Int) *crtBasis {
	if !s.crtDone {
		s.crtDone = true
		n := f.layout.NbLimbs
		fp := make(poly, n+1)
		for j, d := range s.foldDigits {
			fp[j] = new(big.Int).Neg(d)
		}
		fp[n] = big.NewInt(1)
		s.crt = newCRTBasis(polyReduce(fp, q), n, q, func(d int) [][]*big.Int { return s.inverseVandermonde(d, q) })
	}
	return s.crt
}

func polyMulInterval(alo, ahi, blo, bhi []*big.Int) ([]*big.Int, []*big.Int) {
	lo := make([]*big.Int, len(alo)+len(blo)-1)
	hi := make([]*big.Int, len(lo))
	for i := range lo {
		lo[i], hi[i] = new(big.Int), new(big.Int)
	}
	for i := range alo {
		for j := range blo {
			l, h := intervalMul(alo[i], ahi[i], blo[j], bhi[j])
			lo[i+j].Add(lo[i+j], l)
			hi[i+j].Add(hi[i+j], h)
		}
	}
	return lo, hi
}

func balanceOffset(layout Layout, widths []int) *big.Int {
	s := new(big.Int)
	for i, w := range widths {
		s.Add(s, new(big.Int).Lsh(pow2(w-1), uint(layout.LimbBits*i)))
	}
	return s
}

func BalanceHint(_ *big.Int, inputs, outputs []*big.Int) error {
	layout, err := layoutOf(inputs)
	if err != nil {
		return err
	}
	n := layout.NbLimbs
	if len(inputs) < headerLen+n {
		return errors.New("balance: missing modulus")
	}
	mod := layout.recompose(inputs[headerLen : headerLen+n])
	raw := inputs[headerLen+n:]
	widths := layout.reducedWidths(mod.BitLen())
	per := layout.nbPiecesAll(widths)
	if len(raw) != len(outputs) || len(raw)%per != 0 {
		return errors.New("balance: output count mismatch")
	}
	offset := balanceOffset(layout, widths)
	for i := 0; i < len(raw); i += per {
		v := layout.recomposePieces(raw[i:i+per], widths)
		v.Add(v, offset).Mod(v, mod)
		layout.writePieces(outputs[i:i+per], v, widths)
	}
	return nil
}

func floorDiv(a, b *big.Int) *big.Int {
	return new(big.Int).Div(a, b)
}

func PlainCheckHint(nativeModulus *big.Int, inputs, outputs []*big.Int) error {
	position := 0
	next := func() *big.Int {
		v := inputs[position]
		position++
		return v
	}
	nextInt := func() int { return int(next().Int64()) }
	layout, err := layoutOf(inputs)
	if err != nil {
		return err
	}
	position = headerLen
	limbCount := layout.NbLimbs
	modLimbs := make([]*big.Int, limbCount)
	for i := range modLimbs {
		modLimbs[i] = next()
	}
	modulus := layout.recompose(modLimbs)
	hasRemainder, hasQuotient, quotientBits := nextInt(), nextInt(), nextInt()
	var quotientWidths []int
	if hasQuotient == 1 {
		quotientWidths = layout.splitWidths(quotientBits)
	}
	offsetLimbs := make([]*big.Int, 0)
	if hasQuotient == 1 {
		for range quotientWidths {
			offsetLimbs = append(offsetLimbs, next())
		}
	} else {
		next()
	}
	termCount := nextInt()
	type hterm struct {
		coef    *big.Int
		factors []int
	}
	terms := make([]hterm, termCount)
	for i := range terms {
		terms[i].coef = signed(next(), nativeModulus)
		factorCount := nextInt()
		for j := 0; j < factorCount; j++ {
			terms[i].factors = append(terms[i].factors, nextInt())
		}
	}
	elementCount := nextInt()
	elementValues := make([]*big.Int, elementCount)
	for i := range elementValues {
		elementLimbCount := nextInt()
		limbs := make([]*big.Int, elementLimbCount)
		for j := range limbs {
			limbs[j] = signed(next(), nativeModulus)
		}
		elementValues[i] = layout.recompose(limbs)
	}
	if position != len(inputs) {
		return errors.New("inputs not exhausted")
	}
	expressionValue := new(big.Int)
	for _, t := range terms {
		v := new(big.Int).Set(t.coef)
		for _, idx := range t.factors {
			v.Mul(v, elementValues[idx])
		}
		expressionValue.Add(expressionValue, v)
	}
	remainder := new(big.Int)
	if hasRemainder == 1 {
		remainder.Mod(expressionValue, modulus)
	}
	out := outputs
	if hasRemainder == 1 {
		out = layout.writePieces(out, remainder, layout.reducedWidths(modulus.BitLen()))
	}
	if hasQuotient == 1 {
		quotient := new(big.Int).Sub(expressionValue, remainder)
		quotient.Div(quotient, modulus)
		offset := new(big.Int)
		shift := 0
		for i, o := range offsetLimbs {
			offset.Add(offset, new(big.Int).Lsh(o, uint(shift)))
			shift += quotientWidths[i]
		}
		shiftedQuotient := new(big.Int).Add(quotient, offset)
		if shiftedQuotient.Sign() < 0 || shiftedQuotient.BitLen() > quotientBits {
			shiftedQuotient.SetInt64(0)
		}
		out = layout.writePieces(out, shiftedQuotient, quotientWidths)
	}
	if len(out) != 0 {
		return errors.New("output count mismatch")
	}
	return nil
}

func init() {
	solver.RegisterHint(PlainCheckHint, BalanceHint)
}
