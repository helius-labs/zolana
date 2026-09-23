package gnarkffiprover

import (
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark/frontend"
)

// assign fills the circuit's exported variables from witness values keyed by
// field path: a field's name, prefixed by its enclosing struct fields joined
// with "_". Scalars take one decimal value and arrays one per element. Every
// variable must be assigned and every key must name one.
func assign(circuit frontend.Circuit, values map[string][]string) error {
	circuitValue := reflect.ValueOf(circuit)
	if circuitValue.Kind() != reflect.Ptr || circuitValue.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("witness: circuit must be a pointer to struct, got %T", circuit)
	}
	known := make(map[string]bool, len(values))
	if err := assignStruct(circuitValue.Elem(), "", values, known); err != nil {
		return err
	}
	for key := range values {
		if !known[key] {
			return fmt.Errorf("witness: unexpected key %q", key)
		}
	}
	return nil
}

func assignStruct(v reflect.Value, prefix string, values map[string][]string, known map[string]bool) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if sf.PkgPath != "" {
			continue
		}
		key := sf.Name
		if prefix != "" {
			key = prefix + "_" + sf.Name
		}
		field := v.Field(i)
		switch field.Kind() {
		case reflect.Struct:
			if err := assignStruct(field, key, values, known); err != nil {
				return err
			}
		case reflect.Array:
			if err := assignArray(values, key, field); err != nil {
				return err
			}
			known[key] = true
		case reflect.Interface:
			if err := assignScalar(values, key, field); err != nil {
				return err
			}
			known[key] = true
		default:
			return fmt.Errorf("witness: field %q has unsupported kind %s", key, field.Kind())
		}
	}
	return nil
}

func assignScalar(values map[string][]string, key string, destination reflect.Value) error {
	raw, ok := values[key]
	if !ok {
		return fmt.Errorf("witness: missing key %q", key)
	}
	if len(raw) != 1 {
		return fmt.Errorf("witness: key %q expected 1 value, got %d", key, len(raw))
	}
	n, err := parseDecimal(key, 0, raw[0])
	if err != nil {
		return err
	}
	destination.Set(reflect.ValueOf(frontend.Variable(n)))
	return nil
}

func assignArray(values map[string][]string, key string, destination reflect.Value) error {
	raw, ok := values[key]
	if !ok {
		return fmt.Errorf("witness: missing key %q", key)
	}
	if len(raw) != destination.Len() {
		return fmt.Errorf("witness: key %q expected %d values, got %d", key, destination.Len(), len(raw))
	}
	for i, value := range raw {
		n, err := parseDecimal(key, i, value)
		if err != nil {
			return err
		}
		destination.Index(i).Set(reflect.ValueOf(frontend.Variable(n)))
	}
	return nil
}

func parseDecimal(key string, index int, value string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("witness: key %q[%d] invalid decimal %q", key, index, value)
	}
	return n, nil
}
