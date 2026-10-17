// Package r1c emits native rank-one constraints without intermediate wires.
package r1c

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// AssertProduct adds a * b = c directly on R1CS builders, avoiding a product
// wire. Other builders use Mul and AssertIsEqual to check the same relation.
func AssertProduct(api frontend.API, a, b, c frontend.Variable) {
	comp := api.Compiler()
	if va, okA := comp.ConstantValue(a); okA {
		if vb, okB := comp.ConstantValue(b); okB {
			if vc, okC := comp.ConstantValue(c); okC {
				p := comp.Field()
				lhs := new(big.Int).Mul(va, vb)
				lhs.Mod(lhs, p)
				if lhs.Cmp(new(big.Int).Mod(vc, p)) != 0 {
					panic(fmt.Sprintf("r1c: constant row %s * %s = %s does not hold", va, vb, vc))
				}
				return
			}
		}
	}
	la, okA := r1cTerm(comp, a)
	lb, okB := r1cTerm(comp, b)
	lc, okC := r1cTerm(comp, c)
	kv, okKV := comp.(r1cKeyValueStore)
	if !okA || !okB || !okC || !okKV {
		api.AssertIsEqual(api.Mul(a, b), c)
		return
	}
	bp, bID := r1cBlueprint(comp, kv)
	var calldata []uint32
	bp.CompressR1C(&constraint.R1C{L: la, R: lb, O: lc}, &calldata)
	comp.AddInstruction(bID, calldata)
}

// r1cTerm normalizes a canonical expression onto the R1CS constant-one wire.
func r1cTerm(comp frontend.Compiler, v frontend.Variable) (constraint.LinearExpression, bool) {
	l, ok := comp.ToCanonicalVariable(v).(constraint.LinearExpression)
	if !ok {
		return nil, false
	}
	return r1cOnConstantWire(l), true
}

// r1cKeyValueStore matches gnark's internal kvstore.Store, which every
// builder implements.
type r1cKeyValueStore interface {
	SetKeyValue(key, value any)
	GetKeyValue(key any) any
}

type r1cBlueprintKey struct{}

type r1cBlueprintEntry struct {
	bp *constraint.BlueprintGenericR1C
	id constraint.BlueprintID
}

// r1cBlueprint caches the compiler instruction used for an exact multiplication row.
func r1cBlueprint(comp frontend.Compiler, kv r1cKeyValueStore) (*constraint.BlueprintGenericR1C, constraint.BlueprintID) {
	if v := kv.GetKeyValue(r1cBlueprintKey{}); v != nil {
		entry, ok := v.(r1cBlueprintEntry)
		if !ok {
			panic("r1c: stored blueprint has an unexpected type")
		}
		return entry.bp, entry.id
	}
	bp := &constraint.BlueprintGenericR1C{}
	id := comp.AddBlueprint(bp)
	kv.SetKeyValue(r1cBlueprintKey{}, r1cBlueprintEntry{bp: bp, id: id})
	return bp, id
}

// r1cOnConstantWire moves the constant terms that ToCanonicalVariable marks with
// wire MaxUint32 onto the R1CS constant-one wire 0.
func r1cOnConstantWire(l constraint.LinearExpression) constraint.LinearExpression {
	for i := range l {
		if l[i].IsConstant() {
			out := make(constraint.LinearExpression, len(l))
			copy(out, l)
			for j := range out {
				if out[j].IsConstant() {
					out[j].VID = 0
				}
			}
			return out
		}
	}
	return l
}
