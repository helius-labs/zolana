package custom_ring

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/records"
)

var errMissing = errors.New("missing")

// assign sets every variable of dst from the src field of its Go name, an array from a list of its exact length and a nil pointer as zeros.
func assign(dst frontend.Circuit, src any) error {
	return errors.Join(fill(reflect.ValueOf(dst).Elem(), reflect.ValueOf(src), "")...)
}

type viewed interface {
	view() any
}

// fill reads an invalid src, the Elem of a nil pointer, as zeros.
func fill(dst, src reflect.Value, path string) []error {
	if src.Kind() == reflect.Pointer && dst.Kind() != reflect.Interface {
		src = src.Elem()
	}
	if src.IsValid() {
		if v, ok := src.Interface().(viewed); ok {
			src = reflect.ValueOf(v.view())
		}
	}
	var errs []error
	switch dst.Kind() {
	case reflect.Struct:
		for i := range dst.NumField() {
			field := dst.Type().Field(i)
			if field.Tag.Get("gnark") == "-" {
				continue
			}
			if field.Anonymous {
				errs = append(errs, fill(dst.Field(i), src, path)...)
				continue
			}
			name, value := field.Name, reflect.Value{}
			if path != "" {
				name = path + "." + name
			}
			if src.IsValid() {
				if value = src.FieldByName(field.Name); !value.IsValid() {
					errs = append(errs, fmt.Errorf("%s: %w", name, errMissing))
					continue
				}
			}
			errs = append(errs, fill(dst.Field(i), value, name)...)
		}
	case reflect.Array, reflect.Slice:
		if src.IsValid() && (src.Kind() != reflect.Slice || src.Len() != dst.Len()) {
			return []error{fmt.Errorf("%s: expected %d values", path, dst.Len())}
		}
		for i := range dst.Len() {
			value := reflect.Value{}
			if src.IsValid() {
				value = src.Index(i)
			}
			errs = append(errs, fill(dst.Index(i), value, fmt.Sprintf("%s[%d]", path, i))...)
		}
	default:
		value, err := frontend.Variable(0), error(nil)
		if src.IsValid() {
			value, err = variable(src.Interface())
		}
		if err != nil {
			return []error{fmt.Errorf("%s: %w", path, err)}
		}
		dst.Set(reflect.ValueOf(&value).Elem())
	}
	return errs
}

func variable(src any) (frontend.Variable, error) {
	switch v := src.(type) {
	case Field:
		if v.Int != nil {
			return v.Int, nil
		}
	case *Field:
		if v == nil {
			return 0, nil
		}
		return variable(*v)
	case *big.Int:
		if v != nil {
			return v, nil
		}
	case bool:
		if v {
			return 1, nil
		}
		return 0, nil
	case uint8, uint32, uint64, int:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", src)
	}
	return nil, errMissing
}

// A flat path of the wrong length keeps its odd row, fill refuses it.
type quadPath struct {
	Index    uint64
	Siblings [][]Field
}

func newQuadPath(index uint64, flat []Field) quadPath {
	return quadPath{Index: index, Siblings: slices.Collect(slices.Chunk(flat, records.Arity-1))}
}

// recordView mirrors records.QuadRecordOpening field for field.
type recordView struct {
	Next, EscrowKey Field
	Lists           uint64
	Path            quadPath
}

func (r RecordOpening) view() any {
	return recordView{Next: r.Next, EscrowKey: r.EscrowKey, Lists: r.Lists, Path: newQuadPath(r.Index, r.Path)}
}

// memberView mirrors records.QuadOpening field for field.
type memberView struct {
	Present                       bool
	Next, EscrowKey               Field
	Lists                         uint64
	LowMember, LowNext, LowEscrow Field
	LowLists                      uint64
	Path                          quadPath
}

func (m MemberOpening) view() any {
	return memberView{
		Present: m.Present, Next: m.Next, EscrowKey: m.EscrowKey, Lists: m.Lists,
		LowMember: m.LowMember, LowNext: m.LowNext, LowEscrow: m.LowEscrow, LowLists: m.LowLists,
		Path: newQuadPath(m.Index, m.Path),
	}
}

// writeView mirrors registry.RecordWrite field for field.
type writeView struct {
	Entry                         QueueEntry
	Exists                        bool
	OldNext, OldEscrow            Field
	OldLists                      uint64
	Slot                          quadPath
	LowMember, LowNext, LowEscrow Field
	LowLists                      uint64
	Low                           quadPath
}

func (w RecordWrite) view() any {
	return writeView{
		Entry: w.Entry, Exists: w.Exists, OldNext: w.OldNext, OldEscrow: w.OldEscrow, OldLists: w.OldLists,
		Slot:      newQuadPath(w.Index, w.Path),
		LowMember: w.LowMember, LowNext: w.LowNext, LowEscrow: w.LowEscrow, LowLists: w.LowLists,
		Low: newQuadPath(w.LowIndex, w.LowPath),
	}
}
