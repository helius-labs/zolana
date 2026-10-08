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

func Unwrap(nativeModulus *big.Int, inputs, outputs []*big.Int, fn func(modulus *big.Int, nativeInputs, elementInputs, elementOutputs []*big.Int) error) error {
	// 1. Decode the layout, modulus, and native inputs from the hint header.
	layout, err := layoutOf(inputs)
	if err != nil {
		return err
	}
	limbCount := layout.NbLimbs
	position := headerLen
	if len(inputs) < position+limbCount+1 {
		return errors.New("missing hint header")
	}
	modulus := layout.recompose(inputs[position : position+limbCount])
	position += limbCount
	nativeCount := int(inputs[position].Int64())
	position++
	nativeInputs := inputs[position : position+nativeCount]
	position += nativeCount
	// 2. Recompose signed limbs into the emulated input integers.
	var elementInputs []*big.Int
	for position < len(inputs) {
		elementLimbCount := int(inputs[position].Int64())
		position++
		limbs := make([]*big.Int, elementLimbCount)
		for j := range limbs {
			limbs[j] = signed(inputs[position+j], nativeModulus)
		}
		position += elementLimbCount
		elementInputs = append(elementInputs, layout.recompose(limbs))
	}
	widths := layout.reducedWidths(modulus.BitLen())
	piecesPerElement := layout.nbPiecesAll(widths)
	if len(outputs)%piecesPerElement != 0 {
		return errors.New("output count is not a multiple of the element size")
	}
	elementOutputs := make([]*big.Int, len(outputs)/piecesPerElement)
	for i := range elementOutputs {
		elementOutputs[i] = new(big.Int)
	}
	// 3. Run the host computation and encode its outputs as range-check pieces.
	if err := fn(modulus, nativeInputs, elementInputs, elementOutputs); err != nil {
		return err
	}
	remainingOutputs := outputs
	for _, elementValue := range elementOutputs {
		remainingOutputs = layout.writePieces(remainingOutputs, new(big.Int).Mod(elementValue, modulus), widths)
	}
	return nil
}
