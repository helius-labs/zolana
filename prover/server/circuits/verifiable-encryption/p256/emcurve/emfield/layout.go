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
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/multicommit"
)

type Layout struct {
	NbLimbs   int
	LimbBits  int
	PieceBits int
	Lookups   bool
}

var (
	LookupLayout = Layout{NbLimbs: 8, LimbBits: 32, PieceBits: 11, Lookups: true}
	PlainLayout  = Layout{NbLimbs: 8, LimbBits: 32, PieceBits: 32}
)

func LayoutFor(lookups bool) Layout {
	if lookups {
		return LookupLayout
	}
	return PlainLayout
}

func (l Layout) header() []frontend.Variable {
	return []frontend.Variable{l.NbLimbs, l.LimbBits, l.PieceBits}
}

const headerLen = 3

func layoutOf(header []*big.Int) (Layout, error) {
	if len(header) < headerLen {
		return Layout{}, errors.New("missing layout header")
	}
	for _, h := range header[:headerLen] {
		if !h.IsInt64() || h.Int64() <= 0 || h.Int64() > 512 {
			return Layout{}, errors.New("layout mismatch")
		}
	}
	l := Layout{NbLimbs: int(header[0].Int64()), LimbBits: int(header[1].Int64()), PieceBits: int(header[2].Int64())}
	if l.PieceBits > l.LimbBits || l.NbLimbs*l.LimbBits > 512 {
		return Layout{}, errors.New("layout mismatch")
	}
	return l, nil
}

func init() {
	solver.RegisterHint(countHint, decomposeHint)
}

type kvStore interface {
	SetKeyValue(key, value any)
	GetKeyValue(key any) any
}

func store(api frontend.API) kvStore {
	kv, ok := api.Compiler().(kvStore)
	if !ok {
		panic("builder does not implement a key-value store")
	}
	return kv
}

func pow2(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

func (l Layout) reducedWidths(modBits int) []int {
	widths := make([]int, l.NbLimbs)
	rest := modBits
	for i := range widths {
		widths[i] = min(l.LimbBits, rest)
		rest -= widths[i]
	}
	if rest > 0 {
		panic("limbs too narrow for the modulus")
	}
	return widths
}

func (l Layout) splitWidths(total int) []int {
	if total <= 0 {
		return nil
	}
	var widths []int
	for total > 0 {
		w := min(l.LimbBits, total)
		widths = append(widths, w)
		total -= w
	}
	return widths
}

func (l Layout) nbPieces(width int) int {
	return (width + l.PieceBits - 1) / l.PieceBits
}

func (l Layout) nbPiecesAll(widths []int) int {
	n := 0
	for _, w := range widths {
		n += l.nbPieces(w)
	}
	return n
}

func (l Layout) writePieces(out []*big.Int, v *big.Int, widths []int) []*big.Int {
	tmp := new(big.Int).Set(v)
	mask := new(big.Int).Sub(pow2(l.PieceBits), big.NewInt(1))
	for _, w := range widths {
		limb := new(big.Int).And(tmp, new(big.Int).Sub(pow2(w), big.NewInt(1)))
		tmp.Rsh(tmp, uint(w))
		for j := 0; j < l.nbPieces(w); j++ {
			out[0].And(limb, mask)
			limb.Rsh(limb, uint(l.PieceBits))
			out = out[1:]
		}
	}
	return out
}

func (l Layout) recomposePieces(pieces []*big.Int, widths []int) *big.Int {
	v := new(big.Int)
	shift := 0
	for _, w := range widths {
		for k := 0; k < l.nbPieces(w); k++ {
			v.Add(v, new(big.Int).Lsh(pieces[0], uint(shift+k*l.PieceBits)))
			pieces = pieces[1:]
		}
		shift += l.LimbBits
	}
	return v
}

type RangeChecker struct {
	api     frontend.API
	lay     Layout
	queries []frontend.Variable
	partial map[int][]frontend.Variable
}

type rangeCheckerKey struct {
	lookups   bool
	pieceBits int
}

func NewRangeChecker(api frontend.API) *RangeChecker {
	return NewRangeCheckerFor(api, LookupLayout)
}

func NewRangeCheckerFor(api frontend.API, lay Layout) *RangeChecker {
	kv := store(api)
	key := rangeCheckerKey{lay.Lookups, lay.PieceBits}
	if rc, ok := kv.GetKeyValue(key).(*RangeChecker); ok {
		return rc
	}
	rc := &RangeChecker{api: api, lay: lay}
	kv.SetKeyValue(key, rc)
	if lay.Lookups {
		api.Compiler().Defer(rc.build)
	}
	return rc
}

func (rc *RangeChecker) Layout() Layout {
	return rc.lay
}

func (rc *RangeChecker) Check(v frontend.Variable, bits int) {
	if !rc.lay.Lookups {
		checkBits(rc.api, v, bits)
		return
	}
	pieceBits := rc.lay.PieceBits
	switch {
	case bits <= 0:
		rc.api.AssertIsEqual(v, 0)
	case bits == 1:
		rc.api.AssertIsBoolean(v)
	case bits < pieceBits:
		if rc.partial == nil {
			rc.partial = map[int][]frontend.Variable{}
		}
		rc.partial[bits] = append(rc.partial[bits], v)
	case bits == pieceBits:
		rc.queries = append(rc.queries, v)
	default:
		pieces, err := rc.api.Compiler().NewHint(decomposeHint, rc.lay.nbPieces(bits), bits, pieceBits, v)
		if err != nil {
			panic(err)
		}
		rc.api.AssertIsEqual(v, rc.Compose(pieces, bits))
	}
}

func (rc *RangeChecker) Compose(pieces []frontend.Variable, width int) frontend.Variable {
	l := rc.lay
	if len(pieces) != l.nbPieces(width) {
		panic("piece count mismatch")
	}
	sum := frontend.Variable(0)
	for j, piece := range pieces {
		rc.Check(piece, min(l.PieceBits, width-j*l.PieceBits))
		sum = rc.api.Add(sum, rc.api.Mul(piece, pow2(j*l.PieceBits)))
	}
	return sum
}

const tagSeparationLog = 20

func (rc *RangeChecker) build(api frontend.API) error {
	pieceBits := rc.lay.PieceBits
	type tagged struct {
		width   int
		queries []frontend.Variable
	}
	var tags []tagged
	for w := 2; w < pieceBits; w++ {
		vs := rc.partial[w]
		if len(vs) > 1<<w {
			tags = append(tags, tagged{width: w, queries: vs})
			continue
		}
		for _, v := range vs {
			rc.queries = append(rc.queries, v, api.Mul(v, pow2(pieceBits-w)))
		}
	}
	if len(rc.queries) == 0 && len(tags) == 0 {
		return nil
	}
	total := len(rc.queries) + 1<<pieceBits
	for _, tg := range tags {
		total += len(tg.queries) + 1<<tg.width
	}
	if total >= 1<<tagSeparationLog {
		panic("too many range-check queries for the tag separation")
	}
	tableLen := 1 << pieceBits
	inputs := append([]frontend.Variable{tableLen}, rc.queries...)
	counts, err := api.Compiler().NewHint(countHint, tableLen, inputs...)
	if err != nil {
		return err
	}
	toCommit := append(append([]frontend.Variable{}, rc.queries...), counts...)
	tagCounts := make([][]frontend.Variable, len(tags))
	for i, tg := range tags {
		inputs := append([]frontend.Variable{1 << tg.width}, tg.queries...)
		if tagCounts[i], err = api.Compiler().NewHint(countHint, 1<<tg.width, inputs...); err != nil {
			return err
		}
		toCommit = append(append(toCommit, tg.queries...), tagCounts[i]...)
	}
	multicommit.WithCommitment(api, func(api frontend.API, ch frontend.Variable) error {
		alpha := ch
		if len(tags) > 0 {
			for i := 0; i < tagSeparationLog; i++ {
				alpha = api.Mul(alpha, alpha)
			}
		}
		left := frontend.Variable(0)
		for i, m := range counts {
			left = api.Add(left, api.DivUnchecked(m, api.Sub(ch, i)))
		}
		var dens []frontend.Variable
		for _, q := range rc.queries {
			dens = append(dens, api.Sub(ch, q))
		}
		for i, tg := range tags {
			shift := api.Mul(alpha, tg.width)
			for v, m := range tagCounts[i] {
				left = api.Add(left, api.DivUnchecked(m, api.Sub(ch, api.Add(v, shift))))
			}
			for _, q := range tg.queries {
				dens = append(dens, api.Sub(ch, api.Add(q, shift)))
			}
		}
		var invs []frontend.Variable
		if bi, ok := api.(frontend.BatchInverter); ok {
			invs = bi.BatchInvert(dens)
		} else {
			invs = make([]frontend.Variable, len(dens))
			for i := range dens {
				invs[i] = api.Inverse(dens[i])
			}
		}
		right := frontend.Variable(0)
		for _, inv := range invs {
			right = api.Add(right, inv)
		}
		api.AssertIsEqual(left, right)
		return nil
	}, toCommit...)
	return nil
}

func countHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 1 || !inputs[0].IsInt64() || int(inputs[0].Int64()) != len(outputs) {
		return errors.New("table length mismatch")
	}
	for _, out := range outputs {
		out.SetUint64(0)
	}
	n := big.NewInt(int64(len(outputs)))
	for _, q := range inputs[1:] {
		if q.Cmp(n) < 0 {
			outputs[q.Int64()].Add(outputs[q.Int64()], big.NewInt(1))
		}
	}
	return nil
}

func decomposeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return errors.New("expecting width, piece width and value")
	}
	width, piece := int(inputs[0].Int64()), int(inputs[1].Int64())
	if (width+piece-1)/piece != len(outputs) {
		return errors.New("output count mismatch")
	}
	tmp := new(big.Int).Set(inputs[2])
	mask := new(big.Int).Sub(pow2(piece), big.NewInt(1))
	for _, out := range outputs {
		out.And(tmp, mask)
		tmp.Rsh(tmp, uint(piece))
	}
	return nil
}
