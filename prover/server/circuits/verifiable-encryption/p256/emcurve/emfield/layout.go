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

	"github.com/consensys/gnark/frontend"
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

func (l Layout) reducedWidths(modulusBits int) []int {
	widths := make([]int, l.NbLimbs)
	remainingBits := modulusBits
	for i := range widths {
		widths[i] = min(l.LimbBits, remainingBits)
		remainingBits -= widths[i]
	}
	if remainingBits > 0 {
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

func (l Layout) writePieces(outputs []*big.Int, value *big.Int, widths []int) []*big.Int {
	remainingValue := new(big.Int).Set(value)
	mask := new(big.Int).Sub(pow2(l.PieceBits), big.NewInt(1))
	for _, limbWidth := range widths {
		limb := new(big.Int).And(remainingValue, new(big.Int).Sub(pow2(limbWidth), big.NewInt(1)))
		remainingValue.Rsh(remainingValue, uint(limbWidth))
		for j := 0; j < l.nbPieces(limbWidth); j++ {
			outputs[0].And(limb, mask)
			limb.Rsh(limb, uint(l.PieceBits))
			outputs = outputs[1:]
		}
	}
	return outputs
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
