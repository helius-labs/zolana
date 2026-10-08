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

package emcurve

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/multicommit"
)

func init() {
	solver.RegisterHint(p256RowLookupHint, p256RowCountHint)
}

const rowSeparationLog = 8

type rowTable struct {
	api     frontend.API
	nbCols  int
	rows    [][]frontend.Variable
	indices []frontend.Variable
	results [][]frontend.Variable
}

func newRowTable(api frontend.API, nbCols int) *rowTable {
	t := &rowTable{api: api, nbCols: nbCols}
	api.Compiler().Defer(t.build)
	return t
}

func (t *rowTable) insert(row []frontend.Variable) {
	if len(row) != t.nbCols {
		panic("row width mismatch")
	}
	t.rows = append(t.rows, row)
}

func (t *rowTable) lookup(index frontend.Variable) []frontend.Variable {
	inputs := []frontend.Variable{index, len(t.rows), t.nbCols}
	for _, row := range t.rows {
		inputs = append(inputs, row...)
	}
	out, err := t.api.Compiler().NewHint(p256RowLookupHint, t.nbCols, inputs...)
	if err != nil {
		panic(err)
	}
	t.indices = append(t.indices, index)
	t.results = append(t.results, out)
	return out
}

func (t *rowTable) build(api frontend.API) error {
	if len(t.indices) == 0 {
		return nil
	}
	if len(t.indices)+len(t.rows) >= 1<<rowSeparationLog {
		panic("too many rows and queries for the column separation")
	}
	counts, err := api.Compiler().NewHint(p256RowCountHint, len(t.rows), append([]frontend.Variable{len(t.rows)}, t.indices...)...)
	if err != nil {
		return err
	}
	var toCommit []frontend.Variable
	for _, row := range t.rows {
		toCommit = append(toCommit, row...)
	}
	toCommit = append(toCommit, t.indices...)
	for _, res := range t.results {
		toCommit = append(toCommit, res...)
	}
	toCommit = append(toCommit, counts...)
	multicommit.WithCommitment(api, func(api frontend.API, ch frontend.Variable) error {
		coeffs := make([]frontend.Variable, t.nbCols)
		alpha := ch
		for j := range coeffs {
			for i := 0; i < rowSeparationLog; i++ {
				alpha = api.Mul(alpha, alpha)
			}
			coeffs[j] = alpha
		}
		encode := func(index frontend.Variable, vals []frontend.Variable) frontend.Variable {
			v := index
			for j, val := range vals {
				v = api.Add(v, api.Mul(coeffs[j], val))
			}
			return api.Sub(ch, v)
		}
		left := frontend.Variable(0)
		for r, row := range t.rows {
			left = api.Add(left, api.DivUnchecked(counts[r], encode(r, row)))
		}
		dens := make([]frontend.Variable, len(t.indices))
		for i := range t.indices {
			dens[i] = encode(t.indices[i], t.results[i])
		}
		right := frontend.Variable(0)
		if bi, ok := api.(frontend.BatchInverter); ok {
			for _, inv := range bi.BatchInvert(dens) {
				right = api.Add(right, inv)
			}
		} else {
			for _, d := range dens {
				right = api.Add(right, api.Inverse(d))
			}
		}
		api.AssertIsEqual(left, right)
		return nil
	}, toCommit...)
	return nil
}

func p256RowLookupHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 3 {
		return errors.New("missing lookup header")
	}
	nbRows, nbCols := int(inputs[1].Int64()), int(inputs[2].Int64())
	if len(outputs) != nbCols || len(inputs) != 3+nbRows*nbCols {
		return errors.New("lookup shape mismatch")
	}
	for _, out := range outputs {
		out.SetUint64(0)
	}
	if !inputs[0].IsInt64() || inputs[0].Int64() >= int64(nbRows) {
		return nil
	}
	row := inputs[3+int(inputs[0].Int64())*nbCols:]
	for j := range outputs {
		outputs[j].Set(row[j])
	}
	return nil
}

func p256RowCountHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 1 || int(inputs[0].Int64()) != len(outputs) {
		return errors.New("row count mismatch")
	}
	for _, out := range outputs {
		out.SetUint64(0)
	}
	for _, idx := range inputs[1:] {
		if idx.IsInt64() && idx.Int64() < int64(len(outputs)) {
			outputs[idx.Int64()].Add(outputs[idx.Int64()], big.NewInt(1))
		}
	}
	return nil
}
