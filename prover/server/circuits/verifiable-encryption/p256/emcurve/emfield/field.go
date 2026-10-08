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

type Element struct {
	limbs    []frontend.Variable
	lo, hi   []*big.Int
	vlo, vhi *big.Int
	parts    []part
}

type Field struct {
	api     frontend.API
	lay     Layout
	mod     *big.Int
	modBits int
	widths  []int
	modLim  []*big.Int
	rc      *RangeChecker
	plain   *plainState
}

type fieldKey struct {
	mod string
	lay Layout
}

func New(api frontend.API, modulus *big.Int) *Field {
	return NewFor(api, modulus, LookupLayout)
}

func NewFor(api frontend.API, modulus *big.Int, lay Layout) *Field {
	kv := store(api)
	key := fieldKey{modulus.String(), lay}
	if f, ok := kv.GetKeyValue(key).(*Field); ok {
		return f
	}
	f := &Field{
		api:     api,
		lay:     lay,
		mod:     new(big.Int).Set(modulus),
		modBits: modulus.BitLen(),
		widths:  lay.reducedWidths(modulus.BitLen()),
		rc:      NewRangeCheckerFor(api, lay),
	}
	f.modLim = lay.decompose(f.mod, lay.NbLimbs)
	kv.SetKeyValue(key, f)
	f.plain = newPlainState(f)
	return f
}

func (f *Field) Layout() Layout {
	return f.lay
}

func (f *Field) Modulus() *big.Int {
	return new(big.Int).Set(f.mod)
}

func (f *Field) RangeChecker() *RangeChecker {
	return f.rc
}

func (l Layout) decompose(v *big.Int, n int) []*big.Int {
	out := make([]*big.Int, n)
	tmp := new(big.Int).Set(v)
	mask := new(big.Int).Sub(pow2(l.LimbBits), big.NewInt(1))
	for i := range out {
		out[i] = new(big.Int).And(tmp, mask)
		tmp.Rsh(tmp, uint(l.LimbBits))
	}
	if tmp.Sign() != 0 {
		panic("value does not fit the limbs")
	}
	return out
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
	limbs := f.lay.decompose(r, f.lay.NbLimbs)
	e := &Element{limbs: make([]frontend.Variable, f.lay.NbLimbs), lo: limbs, hi: limbs, vlo: r, vhi: r}
	for i := range limbs {
		e.limbs[i] = limbs[i]
	}
	return e
}

func (f *Field) Bounded(limbs []frontend.Variable, widths []int) *Element {
	return f.bounded(limbs, widths)
}

func (f *Field) bounded(limbs []frontend.Variable, widths []int) *Element {
	if len(limbs) != len(widths) {
		panic("limb count mismatch")
	}
	e := &Element{limbs: limbs, lo: make([]*big.Int, len(limbs)), hi: make([]*big.Int, len(limbs))}
	total := 0
	for i, w := range widths {
		e.lo[i] = new(big.Int)
		e.hi[i] = new(big.Int).Sub(pow2(w), big.NewInt(1))
		total = i*f.lay.LimbBits + w
	}
	e.vlo = new(big.Int)
	e.vhi = new(big.Int).Sub(pow2(total), big.NewInt(1))
	return e
}

func (f *Field) WithBounds(limbs []frontend.Variable, lo, hi []*big.Int) *Element {
	if len(limbs) != len(lo) || len(limbs) != len(hi) {
		panic("limb count mismatch")
	}
	e := &Element{limbs: limbs, lo: lo, hi: hi, vlo: new(big.Int), vhi: new(big.Int)}
	for i := range limbs {
		if lo[i].Cmp(hi[i]) > 0 {
			panic("empty limb interval")
		}
		e.vlo.Add(e.vlo, new(big.Int).Lsh(lo[i], uint(f.lay.LimbBits*i)))
		e.vhi.Add(e.vhi, new(big.Int).Lsh(hi[i], uint(f.lay.LimbBits*i)))
	}
	return e
}

func (f *Field) ReducedWidths() []int {
	return append([]int{}, f.widths...)
}

func (f *Field) Reduced(limbs []frontend.Variable) *Element {
	return f.bounded(limbs, f.widths)
}

func (f *Field) FromLimbs(limbs []frontend.Variable) *Element {
	for i, l := range limbs {
		f.rc.Check(l, f.widths[i])
	}
	return f.Reduced(limbs)
}

func (f *Field) fromPieces(pieces []frontend.Variable, widths []int) (*Element, []frontend.Variable) {
	limbs := make([]frontend.Variable, len(widths))
	for i, w := range widths {
		n := f.lay.nbPieces(w)
		limbs[i] = f.rc.Compose(pieces[:n], w)
		pieces = pieces[n:]
	}
	return f.bounded(limbs, widths), pieces
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

func (f *Field) Lin(coefs []int64, elems ...*Element) *Element {
	if len(coefs) != len(elems) {
		panic("coefficient count mismatch")
	}
	n := 0
	for _, e := range elems {
		n = max(n, len(e.limbs))
	}
	r := &Element{limbs: make([]frontend.Variable, n), lo: make([]*big.Int, n), hi: make([]*big.Int, n), vlo: new(big.Int), vhi: new(big.Int)}
	for i := range r.limbs {
		r.limbs[i] = 0
		r.lo[i] = new(big.Int)
		r.hi[i] = new(big.Int)
	}
	for k, e := range elems {
		c := big.NewInt(coefs[k])
		r.parts = append(r.parts, part{coef: c, e: e})
		for i := range e.limbs {
			r.limbs[i] = f.api.Add(r.limbs[i], f.api.Mul(e.limbs[i], c))
			a, b := new(big.Int).Mul(e.lo[i], c), new(big.Int).Mul(e.hi[i], c)
			if c.Sign() < 0 {
				a, b = b, a
			}
			r.lo[i].Add(r.lo[i], a)
			r.hi[i].Add(r.hi[i], b)
		}
		a, b := new(big.Int).Mul(e.vlo, c), new(big.Int).Mul(e.vhi, c)
		if c.Sign() < 0 {
			a, b = b, a
		}
		r.vlo.Add(r.vlo, a)
		r.vhi.Add(r.vhi, b)
	}
	return r
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

func (f *Field) Select(b frontend.Variable, x, y *Element) *Element {
	n := max(len(x.limbs), len(y.limbs))
	r := &Element{limbs: make([]frontend.Variable, n), lo: make([]*big.Int, n), hi: make([]*big.Int, n)}
	limb := func(e *Element, i int) (frontend.Variable, *big.Int, *big.Int) {
		if i < len(e.limbs) {
			return e.limbs[i], e.lo[i], e.hi[i]
		}
		return 0, new(big.Int), new(big.Int)
	}
	for i := range r.limbs {
		xv, xl, xh := limb(x, i)
		yv, yl, yh := limb(y, i)
		r.limbs[i] = f.api.Select(b, xv, yv)
		r.lo[i] = minInt(xl, yl)
		r.hi[i] = maxInt(xh, yh)
	}
	r.vlo = minInt(x.vlo, y.vlo)
	r.vhi = maxInt(x.vhi, y.vhi)
	return r
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
	inputs := f.lay.header()
	for _, l := range f.modLim {
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
	per := f.lay.nbPiecesAll(f.widths)
	pieces, err := f.api.Compiler().NewHint(fn, nbOutputs*per, f.hintInputs(natives, elems)...)
	if err != nil {
		panic(fmt.Sprintf("field hint: %v", err))
	}
	out := make([]*Element, nbOutputs)
	for i := range out {
		out[i], pieces = f.fromPieces(pieces, f.widths)
	}
	return out
}
