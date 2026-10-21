package custom_ring

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func ringOf(t testing.TB, circuit common.CircuitType) RingCircuit {
	t.Helper()
	ring, err := Ring(circuit)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// requestOf is the inverse of assign, the request a client sends for assignment.
func requestOf(t testing.TB, circuit common.CircuitType, assignment frontend.Circuit) any {
	t.Helper()
	params := ringOf(t, circuit).params()
	dst := reflect.ValueOf(params).Elem()
	dst.FieldByName("CircuitType").SetString(string(circuit))
	if err := errors.Join(unfill(dst, reflect.ValueOf(assignment).Elem(), "")...); err != nil {
		t.Fatal(err)
	}
	return params
}

type unviewed interface {
	request() any
}

func unfill(dst, src reflect.Value, path string) []error {
	if dst.Kind() == reflect.Pointer {
		dst.Set(reflect.New(dst.Type().Elem()))
		return unfill(dst.Elem(), src, path)
	}
	if v, ok := dst.Interface().(viewed); ok {
		view := reflect.New(reflect.TypeOf(v.view())).Elem()
		errs := unfill(view, src, path)
		dst.Set(reflect.ValueOf(view.Interface().(unviewed).request()))
		return errs
	}
	if src.Kind() == reflect.Interface {
		src = src.Elem()
	}
	switch {
	case dst.Type() == reflect.TypeOf(Field{}):
		dst.Set(reflect.ValueOf(Field{fieldOf(src)}))
	case dst.Kind() == reflect.Struct:
		var errs []error
		for i := range dst.NumField() {
			field := dst.Type().Field(i)
			if field.Anonymous {
				errs = append(errs, unfill(dst.Field(i), src, path)...)
				continue
			}
			if field.Name == "CircuitType" {
				continue
			}
			value := src.FieldByName(field.Name)
			if !value.IsValid() {
				errs = append(errs, fmt.Errorf("%s.%s: no circuit value", path, field.Name))
				continue
			}
			errs = append(errs, unfill(dst.Field(i), value, path+"."+field.Name)...)
		}
		return errs
	case dst.Kind() == reflect.Slice:
		dst.Set(reflect.MakeSlice(dst.Type(), src.Len(), src.Len()))
		var errs []error
		for i := range src.Len() {
			errs = append(errs, unfill(dst.Index(i), src.Index(i), fmt.Sprintf("%s[%d]", path, i))...)
		}
		return errs
	case dst.Kind() == reflect.Bool:
		dst.SetBool(fieldOf(src).Sign() != 0)
	case dst.CanUint():
		value := fieldOf(src)
		if !value.IsUint64() || dst.OverflowUint(value.Uint64()) {
			return []error{fmt.Errorf("%s: %s overflows %s", path, value, dst.Type())}
		}
		dst.SetUint(value.Uint64())
	default:
		return []error{fmt.Errorf("%s: no request value for %s", path, dst.Type())}
	}
	return nil
}

func fieldOf(src reflect.Value) *big.Int {
	var element fr.Element
	if _, err := element.SetInterface(src.Interface()); err != nil {
		panic(fmt.Sprintf("custom-ring test: %v", err))
	}
	return element.BigInt(new(big.Int))
}

func (v quadPath) flat() []Field {
	var flat []Field
	for _, row := range v.Siblings {
		flat = append(flat, row...)
	}
	return flat
}

func (v recordView) request() any {
	return RecordOpening{Next: v.Next, Lists: v.Lists, EscrowKey: v.EscrowKey, Index: v.Path.Index, Path: v.Path.flat()}
}

func (v memberView) request() any {
	return MemberOpening{
		Present:       v.Present,
		RecordOpening: RecordOpening{Next: v.Next, Lists: v.Lists, EscrowKey: v.EscrowKey, Index: v.Path.Index, Path: v.Path.flat()},
		LowMember:     v.LowMember, LowNext: v.LowNext, LowLists: v.LowLists, LowEscrow: v.LowEscrow,
	}
}

func (v writeView) request() any {
	return RecordWrite{
		Entry: v.Entry, Exists: v.Exists, OldNext: v.OldNext, OldLists: v.OldLists, OldEscrow: v.OldEscrow,
		Index: v.Slot.Index, Path: v.Slot.flat(),
		LowMember: v.LowMember, LowNext: v.LowNext, LowLists: v.LowLists, LowEscrow: v.LowEscrow,
		LowIndex: v.Low.Index, LowPath: v.Low.flat(),
	}
}

func mustMarshal(t testing.TB, params any) []byte {
	t.Helper()
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// decodeParams round trips params through the wire format, as the server reads them.
func decodeParams(t testing.TB, circuit common.CircuitType, params any) frontend.Circuit {
	t.Helper()
	return decodePayload(t, circuit, mustMarshal(t, params))
}

func decodePayload(t testing.TB, circuit common.CircuitType, payload []byte) frontend.Circuit {
	t.Helper()
	assignment, err := Decode(circuit, payload)
	if err != nil {
		t.Fatalf("%s: %v", circuit, err)
	}
	return assignment
}

func verifyProof(ps *common.RingProofSystem, proof *common.Proof, assignment frontend.Circuit) error {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(proof.Proof, ps.VerifyingKey, witness)
}
