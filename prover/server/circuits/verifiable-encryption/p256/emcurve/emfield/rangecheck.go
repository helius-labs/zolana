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

func init() {
	solver.RegisterHint(countHint, decomposeHint)
}

type RangeChecker struct {
	api     frontend.API
	layout  Layout
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

func NewRangeCheckerFor(api frontend.API, layout Layout) *RangeChecker {
	kv := store(api)
	key := rangeCheckerKey{layout.Lookups, layout.PieceBits}
	if rc, ok := kv.GetKeyValue(key).(*RangeChecker); ok {
		return rc
	}
	rc := &RangeChecker{api: api, layout: layout}
	kv.SetKeyValue(key, rc)
	if layout.Lookups {
		api.Compiler().Defer(rc.build)
	}
	return rc
}

func (rc *RangeChecker) Layout() Layout {
	return rc.layout
}

func (rc *RangeChecker) Check(v frontend.Variable, bits int) {
	if !rc.layout.Lookups {
		checkBits(rc.api, v, bits)
		return
	}
	pieceBits := rc.layout.PieceBits
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
		pieces, err := rc.api.Compiler().NewHint(decomposeHint, rc.layout.nbPieces(bits), bits, pieceBits, v)
		if err != nil {
			panic(err)
		}
		rc.api.AssertIsEqual(v, rc.Compose(pieces, bits))
	}
}

func (rc *RangeChecker) Compose(pieces []frontend.Variable, width int) frontend.Variable {
	l := rc.layout
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
	// 1. Group narrow ranges by width, or scale sparse queries into the main table.
	pieceBits := rc.layout.PieceBits
	type tagged struct {
		width   int
		queries []frontend.Variable
	}
	var tags []tagged
	for w := 2; w < pieceBits; w++ {
		queries := rc.partial[w]
		if len(queries) > 1<<w {
			tags = append(tags, tagged{width: w, queries: queries})
			continue
		}
		for _, v := range queries {
			rc.queries = append(rc.queries, v, api.Mul(v, pow2(pieceBits-w)))
		}
	}
	if len(rc.queries) == 0 && len(tags) == 0 {
		return nil
	}
	total := len(rc.queries) + 1<<pieceBits
	for _, tag := range tags {
		total += len(tag.queries) + 1<<tag.width
	}
	if total >= 1<<tagSeparationLog {
		panic("too many range-check queries for the tag separation")
	}
	// 2. Hint multiplicities and bind every query and count before the challenge.
	tableLen := 1 << pieceBits
	inputs := append([]frontend.Variable{tableLen}, rc.queries...)
	counts, err := api.Compiler().NewHint(countHint, tableLen, inputs...)
	if err != nil {
		return err
	}
	committedValues := append(append([]frontend.Variable{}, rc.queries...), counts...)
	tagCounts := make([][]frontend.Variable, len(tags))
	for i, tag := range tags {
		inputs := append([]frontend.Variable{1 << tag.width}, tag.queries...)
		if tagCounts[i], err = api.Compiler().NewHint(countHint, 1<<tag.width, inputs...); err != nil {
			return err
		}
		committedValues = append(append(committedValues, tag.queries...), tagCounts[i]...)
	}
	// 3. Separate tagged ranges and equate their table and query log-derivative sums.
	multicommit.WithCommitment(api, func(api frontend.API, challenge frontend.Variable) error {
		alpha := challenge
		if len(tags) > 0 {
			for i := 0; i < tagSeparationLog; i++ {
				alpha = api.Mul(alpha, alpha)
			}
		}
		tableSum := frontend.Variable(0)
		for i, m := range counts {
			tableSum = api.Add(tableSum, api.DivUnchecked(m, api.Sub(challenge, i)))
		}
		var queryDenominators []frontend.Variable
		for _, q := range rc.queries {
			queryDenominators = append(queryDenominators, api.Sub(challenge, q))
		}
		for i, tag := range tags {
			shift := api.Mul(alpha, tag.width)
			for v, m := range tagCounts[i] {
				tableSum = api.Add(tableSum, api.DivUnchecked(m, api.Sub(challenge, api.Add(v, shift))))
			}
			for _, q := range tag.queries {
				queryDenominators = append(queryDenominators, api.Sub(challenge, api.Add(q, shift)))
			}
		}
		var queryInverses []frontend.Variable
		if batchInverter, ok := api.(frontend.BatchInverter); ok {
			queryInverses = batchInverter.BatchInvert(queryDenominators)
		} else {
			queryInverses = make([]frontend.Variable, len(queryDenominators))
			for i := range queryDenominators {
				queryInverses[i] = api.Inverse(queryDenominators[i])
			}
		}
		querySum := frontend.Variable(0)
		for _, inv := range queryInverses {
			querySum = api.Add(querySum, inv)
		}
		api.AssertIsEqual(tableSum, querySum)
		return nil
	}, committedValues...)
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
	width, pieceBits := int(inputs[0].Int64()), int(inputs[1].Int64())
	if (width+pieceBits-1)/pieceBits != len(outputs) {
		return errors.New("output count mismatch")
	}
	remainingValue := new(big.Int).Set(inputs[2])
	mask := new(big.Int).Sub(pow2(pieceBits), big.NewInt(1))
	for _, out := range outputs {
		out.And(remainingValue, mask)
		remainingValue.Rsh(remainingValue, uint(pieceBits))
	}
	return nil
}
