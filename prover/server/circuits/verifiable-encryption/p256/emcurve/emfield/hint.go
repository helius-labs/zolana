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
)

func Unwrap(q *big.Int, inputs, outputs []*big.Int, fn func(mod *big.Int, natives, in, out []*big.Int) error) error {
	lay, err := layoutOf(inputs)
	if err != nil {
		return err
	}
	n := lay.NbLimbs
	pos := headerLen
	if len(inputs) < pos+n+1 {
		return errors.New("missing hint header")
	}
	mod := lay.recompose(inputs[pos : pos+n])
	pos += n
	nbNatives := int(inputs[pos].Int64())
	pos++
	natives := inputs[pos : pos+nbNatives]
	pos += nbNatives
	var in []*big.Int
	for pos < len(inputs) {
		nl := int(inputs[pos].Int64())
		pos++
		limbs := make([]*big.Int, nl)
		for j := range limbs {
			limbs[j] = signed(inputs[pos+j], q)
		}
		pos += nl
		in = append(in, lay.recompose(limbs))
	}
	widths := lay.reducedWidths(mod.BitLen())
	per := lay.nbPiecesAll(widths)
	if len(outputs)%per != 0 {
		return errors.New("output count is not a multiple of the element size")
	}
	out := make([]*big.Int, len(outputs)/per)
	for i := range out {
		out[i] = new(big.Int)
	}
	if err := fn(mod, natives, in, out); err != nil {
		return err
	}
	rest := outputs
	for _, v := range out {
		rest = lay.writePieces(rest, new(big.Int).Mod(v, mod), widths)
	}
	return nil
}
