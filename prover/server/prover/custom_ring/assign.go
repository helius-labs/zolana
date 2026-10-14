package custom_ring

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark/frontend"
)

var errMissing = errors.New("missing")

// assign sets every variable of dst from the src field with the same Go name.
// An array takes a list of its exact length, a nil pointer assigns zeros.
func assign(dst frontend.Circuit, src any) error {
	return errors.Join(fill(reflect.ValueOf(dst).Elem(), reflect.ValueOf(src), "")...)
}

func fill(dst, src reflect.Value, path string) []error {
	if src.Kind() == reflect.Pointer && dst.Kind() != reflect.Interface {
		if src.IsNil() {
			zero(dst)
			return nil
		}
		src = src.Elem()
	}
	switch dst.Kind() {
	case reflect.Struct:
		var errs []error
		for i := range dst.NumField() {
			field := dst.Type().Field(i)
			if field.Anonymous {
				errs = append(errs, fill(dst.Field(i), src, path)...)
				continue
			}
			name := field.Name
			if path != "" {
				name = path + "." + name
			}
			value := src.FieldByName(field.Name)
			if !value.IsValid() {
				errs = append(errs, fmt.Errorf("%s: %w", name, errMissing))
				continue
			}
			errs = append(errs, fill(dst.Field(i), value, name)...)
		}
		return errs
	case reflect.Array:
		if src.Kind() != reflect.Slice || src.Len() != dst.Len() {
			return []error{fmt.Errorf("%s: expected %d values", path, dst.Len())}
		}
		var errs []error
		for i := range dst.Len() {
			errs = append(errs, fill(dst.Index(i), src.Index(i), fmt.Sprintf("%s[%d]", path, i))...)
		}
		return errs
	}
	value, err := variable(src.Interface())
	if err != nil {
		return []error{fmt.Errorf("%s: %w", path, err)}
	}
	dst.Set(reflect.ValueOf(&value).Elem())
	return nil
}

func variable(src any) (frontend.Variable, error) {
	switch v := src.(type) {
	case Field:
		if v.Int != nil {
			return v.Int, nil
		}
	case *big.Int:
		if v != nil {
			return v, nil
		}
	case Bytes:
		if v != nil {
			return new(big.Int).SetBytes(v), nil
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

func zero(dst reflect.Value) {
	switch dst.Kind() {
	case reflect.Struct:
		for i := range dst.NumField() {
			zero(dst.Field(i))
		}
	case reflect.Array:
		for i := range dst.Len() {
			zero(dst.Index(i))
		}
	default:
		dst.Set(reflect.ValueOf(frontend.Variable(0)))
	}
}
