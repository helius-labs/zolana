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
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type part struct {
	coef *big.Int
	e    *Element
}

// Element tracks circuit limbs and compile-time bounds for their integer values.
// Bounds are metadata; constructors such as Bounded and Reduced do not prove them.
type Element struct {
	limbs              []frontend.Variable
	lo, hi             []*big.Int
	valueMin, valueMax *big.Int
	parts              []part
}

type Field struct {
	api          frontend.API
	layout       Layout
	mod          *big.Int
	modulusBits  int
	widths       []int
	modulusLimbs []*big.Int
	rc           *RangeChecker
	arithmetic   *arithmeticState
}

type fieldKey struct {
	mod    string
	layout Layout
}

func New(api frontend.API, modulus *big.Int) *Field {
	return NewFor(api, modulus, LookupLayout)
}

func NewFor(api frontend.API, modulus *big.Int, layout Layout) *Field {
	kv := store(api)
	key := fieldKey{modulus.String(), layout}
	if f, ok := kv.GetKeyValue(key).(*Field); ok {
		return f
	}
	f := &Field{
		api:         api,
		layout:      layout,
		mod:         new(big.Int).Set(modulus),
		modulusBits: modulus.BitLen(),
		widths:      layout.reducedWidths(modulus.BitLen()),
		rc:          NewRangeCheckerFor(api, layout),
	}
	f.modulusLimbs = layout.decompose(f.mod, layout.NbLimbs)
	kv.SetKeyValue(key, f)
	f.arithmetic = newArithmeticState(f)
	return f
}

func (f *Field) Layout() Layout {
	return f.layout
}

func (f *Field) Modulus() *big.Int {
	return new(big.Int).Set(f.mod)
}

func (f *Field) RangeChecker() *RangeChecker {
	return f.rc
}

func (l Layout) decompose(value *big.Int, limbCount int) []*big.Int {
	limbs := make([]*big.Int, limbCount)
	remainingValue := new(big.Int).Set(value)
	mask := new(big.Int).Sub(pow2(l.LimbBits), big.NewInt(1))
	for i := range limbs {
		limbs[i] = new(big.Int).And(remainingValue, mask)
		remainingValue.Rsh(remainingValue, uint(l.LimbBits))
	}
	if remainingValue.Sign() != 0 {
		panic("value does not fit the limbs")
	}
	return limbs
}

func (l Layout) recompose(limbs []*big.Int) *big.Int {
	v := new(big.Int)
	for i := len(limbs) - 1; i >= 0; i-- {
		v.Lsh(v, uint(l.LimbBits)).Add(v, limbs[i])
	}
	return v
}

func (f *Field) Const(v *big.Int) *Element {
	r := new(big.Int).Mod(v, f.mod)
	limbs := f.layout.decompose(r, f.layout.NbLimbs)
	e := &Element{limbs: make([]frontend.Variable, f.layout.NbLimbs), lo: limbs, hi: limbs, valueMin: r, valueMax: r}
	for i := range limbs {
		e.limbs[i] = limbs[i]
	}
	return e
}

// Bounded attaches known unsigned bounds; the caller must establish them in the circuit.
func (f *Field) Bounded(limbs []frontend.Variable, widths []int) *Element {
	if len(limbs) != len(widths) {
		panic("limb count mismatch")
	}
	e := &Element{limbs: limbs, lo: make([]*big.Int, len(limbs)), hi: make([]*big.Int, len(limbs))}
	total := 0
	for i, w := range widths {
		e.lo[i] = new(big.Int)
		e.hi[i] = new(big.Int).Sub(pow2(w), big.NewInt(1))
		total = i*f.layout.LimbBits + w
	}
	e.valueMin = new(big.Int)
	e.valueMax = new(big.Int).Sub(pow2(total), big.NewInt(1))
	return e
}

func (f *Field) WithBounds(limbs []frontend.Variable, lo, hi []*big.Int) *Element {
	if len(limbs) != len(lo) || len(limbs) != len(hi) {
		panic("limb count mismatch")
	}
	e := &Element{limbs: limbs, lo: lo, hi: hi, valueMin: new(big.Int), valueMax: new(big.Int)}
	for i := range limbs {
		if lo[i].Cmp(hi[i]) > 0 {
			panic("empty limb interval")
		}
		e.valueMin.Add(e.valueMin, new(big.Int).Lsh(lo[i], uint(f.layout.LimbBits*i)))
		e.valueMax.Add(e.valueMax, new(big.Int).Lsh(hi[i], uint(f.layout.LimbBits*i)))
	}
	return e
}

func (f *Field) ReducedWidths() []int {
	return append([]int{}, f.widths...)
}

// Reduced attaches the field layout bounds without adding range constraints.
func (f *Field) Reduced(limbs []frontend.Variable) *Element {
	return f.Bounded(limbs, f.widths)
}

// FromLimbs range-checks each limb before attaching the field layout bounds.
func (f *Field) FromLimbs(limbs []frontend.Variable) *Element {
	for i, l := range limbs {
		f.rc.Check(l, f.widths[i])
	}
	return f.Reduced(limbs)
}

func (f *Field) fromPieces(pieces []frontend.Variable, widths []int) (*Element, []frontend.Variable) {
	limbs := make([]frontend.Variable, len(widths))
	for i, limbWidth := range widths {
		pieceCount := f.layout.nbPieces(limbWidth)
		limbs[i] = f.rc.Compose(pieces[:pieceCount], limbWidth)
		pieces = pieces[pieceCount:]
	}
	return f.Bounded(limbs, widths), pieces
}

func (e *Element) Limbs() []frontend.Variable {
	return e.limbs
}

func (e *Element) IsReduced(widths []int) bool {
	if len(e.limbs) != len(widths) || e.parts != nil {
		return false
	}
	for i, w := range widths {
		if e.lo[i].Sign() < 0 || e.hi[i].BitLen() > w {
			return false
		}
	}
	return true
}

func (f *Field) Lin(coefficients []int64, elements ...*Element) *Element {
	if len(coefficients) != len(elements) {
		panic("coefficient count mismatch")
	}
	limbCount := 0
	for _, e := range elements {
		limbCount = max(limbCount, len(e.limbs))
	}
	combination := &Element{limbs: make([]frontend.Variable, limbCount), lo: make([]*big.Int, limbCount), hi: make([]*big.Int, limbCount), valueMin: new(big.Int), valueMax: new(big.Int)}
	for i := range combination.limbs {
		combination.limbs[i] = 0
		combination.lo[i] = new(big.Int)
		combination.hi[i] = new(big.Int)
	}
	for k, e := range elements {
		coefficient := big.NewInt(coefficients[k])
		combination.parts = append(combination.parts, part{coef: coefficient, e: e})
		for i := range e.limbs {
			combination.limbs[i] = f.api.Add(combination.limbs[i], f.api.Mul(e.limbs[i], coefficient))
			scaledMin, scaledMax := new(big.Int).Mul(e.lo[i], coefficient), new(big.Int).Mul(e.hi[i], coefficient)
			if coefficient.Sign() < 0 {
				scaledMin, scaledMax = scaledMax, scaledMin
			}
			combination.lo[i].Add(combination.lo[i], scaledMin)
			combination.hi[i].Add(combination.hi[i], scaledMax)
		}
		scaledMin, scaledMax := new(big.Int).Mul(e.valueMin, coefficient), new(big.Int).Mul(e.valueMax, coefficient)
		if coefficient.Sign() < 0 {
			scaledMin, scaledMax = scaledMax, scaledMin
		}
		combination.valueMin.Add(combination.valueMin, scaledMin)
		combination.valueMax.Add(combination.valueMax, scaledMax)
	}
	return combination
}

func (f *Field) Add(a, b *Element) *Element {
	return f.Lin([]int64{1, 1}, a, b)
}

func (f *Field) Sub(a, b *Element) *Element {
	return f.Lin([]int64{1, -1}, a, b)
}

func (f *Field) Neg(a *Element) *Element {
	return f.Lin([]int64{-1}, a)
}

func (f *Field) MulConst(a *Element, c int64) *Element {
	return f.Lin([]int64{c}, a)
}

func (f *Field) Select(selector frontend.Variable, x, y *Element) *Element {
	limbCount := max(len(x.limbs), len(y.limbs))
	selected := &Element{limbs: make([]frontend.Variable, limbCount), lo: make([]*big.Int, limbCount), hi: make([]*big.Int, limbCount)}
	limb := func(e *Element, i int) (frontend.Variable, *big.Int, *big.Int) {
		if i < len(e.limbs) {
			return e.limbs[i], e.lo[i], e.hi[i]
		}
		return 0, new(big.Int), new(big.Int)
	}
	for i := range selected.limbs {
		xValue, xMin, xMax := limb(x, i)
		yValue, yMin, yMax := limb(y, i)
		selected.limbs[i] = f.api.Select(selector, xValue, yValue)
		selected.lo[i] = minInt(xMin, yMin)
		selected.hi[i] = maxInt(xMax, yMax)
	}
	selected.valueMin = minInt(x.valueMin, y.valueMin)
	selected.valueMax = maxInt(x.valueMax, y.valueMax)
	return selected
}

func minInt(a, b *big.Int) *big.Int {
	if a.Cmp(b) < 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}

func maxInt(a, b *big.Int) *big.Int {
	if a.Cmp(b) > 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}

func absMax(lo, hi *big.Int) *big.Int {
	return maxInt(new(big.Int).Abs(lo), new(big.Int).Abs(hi))
}

func (f *Field) hintInputs(natives []frontend.Variable, elems []*Element) []frontend.Variable {
	inputs := f.layout.header()
	for _, l := range f.modulusLimbs {
		inputs = append(inputs, l)
	}
	inputs = append(inputs, len(natives))
	inputs = append(inputs, natives...)
	for _, e := range elems {
		inputs = append(inputs, len(e.limbs))
		inputs = append(inputs, e.limbs...)
	}
	return inputs
}

func (f *Field) Hint(fn func(*big.Int, []*big.Int, []*big.Int) error, nbOutputs int, natives []frontend.Variable, elems ...*Element) []*Element {
	piecesPerElement := f.layout.nbPiecesAll(f.widths)
	pieces, err := f.api.Compiler().NewHint(fn, nbOutputs*piecesPerElement, f.hintInputs(natives, elems)...)
	if err != nil {
		panic(fmt.Sprintf("field hint: %v", err))
	}
	elements := make([]*Element, nbOutputs)
	for i := range elements {
		elements[i], pieces = f.fromPieces(pieces, f.widths)
	}
	return elements
}
