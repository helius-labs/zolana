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

// An invalid src, which a nil pointer yields, assigns zeros.
func fill(dst, src reflect.Value, path string) []error {
	if src.Kind() == reflect.Pointer && dst.Kind() != reflect.Interface {
		src = src.Elem()
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
	case reflect.Array:
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
