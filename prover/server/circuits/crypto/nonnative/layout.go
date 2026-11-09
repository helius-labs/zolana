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

package nonnative

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type Layout struct {
	NbLimbs   int
	LimbBits  int
	PieceBits int
}

// Encodes the compile-time limb layout in the hint ABI.
func (l Layout) header() []frontend.Variable {
	return []frontend.Variable{l.NbLimbs, l.LimbBits, l.PieceBits}
}

const headerLen = 3

func (l Layout) check(modulusBits int) error {
	if l.NbLimbs <= 0 || l.LimbBits <= 0 || l.PieceBits <= 0 {
		return errors.New("layout fields must be positive")
	}
	if l.PieceBits > l.LimbBits || l.NbLimbs*l.LimbBits > 512 {
		return errors.New("layout mismatch")
	}
	if l.NbLimbs*l.LimbBits < modulusBits {
		return errors.New("limbs too narrow for the modulus")
	}
	if (l.NbLimbs-1)*l.LimbBits >= modulusBits {
		return errors.New("layout has a zero-width limb")
	}
	return nil
}

// Hint inputs are prover-controlled, validated before any limb slice is read.
func decodeLayout(inputs []*big.Int) (Layout, *big.Int, error) {
	if len(inputs) < headerLen {
		return Layout{}, nil, errors.New("missing layout header")
	}
	for _, h := range inputs[:headerLen] {
		if !h.IsInt64() || h.Int64() <= 0 || h.Int64() > 512 {
			return Layout{}, nil, errors.New("layout mismatch")
		}
	}
	l := Layout{NbLimbs: int(inputs[0].Int64()), LimbBits: int(inputs[1].Int64()), PieceBits: int(inputs[2].Int64())}
	if len(inputs) < headerLen+l.NbLimbs {
		return Layout{}, nil, errors.New("missing modulus limbs")
	}
	modulus := l.recompose(inputs[headerLen : headerLen+l.NbLimbs])
	if err := l.check(modulus.BitLen()); err != nil {
		return Layout{}, nil, err
	}
	return l, modulus, nil
}

type kvStore interface {
	SetKeyValue(key, value any)
	GetKeyValue(key any) any
}

// Requires the compiler cache used to share field arguments and product kernels.
func store(api frontend.API) kvStore {
	kv, ok := api.Compiler().(kvStore)
	if !ok {
		panic("builder does not implement a key-value store")
	}
	return kv
}

// Returns an exact public power of two for bounds and radix constants.
func pow2(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

// Derives unsigned limb widths from the modulus size and rejects insufficient capacity.
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

// Partitions a public bit count into limb widths.
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

// Returns the number of range-check pieces needed for the requested width.
func (l Layout) nbPieces(width int) int {
	return (width + l.PieceBits - 1) / l.PieceBits
}

// Totals the range-check pieces needed for a list of limb widths.
func (l Layout) nbPiecesAll(widths []int) int {
	n := 0
	for _, w := range widths {
		n += l.nbPieces(w)
	}
	return n
}

// Suggests little-endian hint pieces. Callers must constrain their widths and relation.
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

// Reconstructs a host integer from the hint piece layout.
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
