package witness

import (
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark/frontend"
)

func Assign(circuit frontend.Circuit, witnessValues map[string][]string) error {
	circuitValue := reflect.ValueOf(circuit)
	if circuitValue.Kind() != reflect.Ptr || circuitValue.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("witness: circuit must be a pointer to struct, got %T", circuit)
	}

	known := make(map[string]bool, len(witnessValues))
	if err := assignStruct(circuitValue.Elem(), "", witnessValues, known); err != nil {
		return err
	}
	return checkUnexpected(witnessValues, known)
}

func assignStruct(v reflect.Value, prefix string, witnessValues map[string][]string, known map[string]bool) error {
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
			if err := assignStruct(field, key, witnessValues, known); err != nil {
				return err
			}
		case reflect.Array:
			if err := assignArrayField(witnessValues, key, field); err != nil {
				return err
			}
			known[key] = true
		case reflect.Interface:
			if err := assignScalarField(witnessValues, key, field); err != nil {
				return err
			}
			known[key] = true
		default:
			return fmt.Errorf("witness: field %q has unsupported kind %s", key, field.Kind())
		}
	}
	return nil
}

func assignScalarField(witnessValues map[string][]string, key string, destination reflect.Value) error {
	n, err := singleBigInt(witnessValues, key)
	if err != nil {
		return err
	}
	destination.Set(reflect.ValueOf(frontend.Variable(n)))
	return nil
}

func assignArrayField(witnessValues map[string][]string, key string, destination reflect.Value) error {
	vals, ok := witnessValues[key]
	if !ok {
		return fmt.Errorf("witness: missing key %q", key)
	}
	if len(vals) != destination.Len() {
		return fmt.Errorf("witness: key %q expected %d values, got %d", key, destination.Len(), len(vals))
	}
	for i, raw := range vals {
		n, ok := new(big.Int).SetString(raw, 10)
		if !ok {
			return fmt.Errorf("witness: key %q[%d] invalid decimal %q", key, i, raw)
		}
		destination.Index(i).Set(reflect.ValueOf(frontend.Variable(n)))
	}
	return nil
}

func checkUnexpected(witnessValues map[string][]string, known map[string]bool) error {
	for k := range witnessValues {
		if !known[k] {
			return fmt.Errorf("witness: unexpected key %q", k)
		}
	}
	return nil
}

func singleBigInt(witnessValues map[string][]string, key string) (*big.Int, error) {
	vals, ok := witnessValues[key]
	if !ok {
		return nil, fmt.Errorf("witness: missing key %q", key)
	}
	if len(vals) != 1 {
		return nil, fmt.Errorf("witness: key %q expected 1 value, got %d", key, len(vals))
	}
	var raw string
	for _, v := range vals {
		raw = v
	}
	n, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		return nil, fmt.Errorf("witness: key %q invalid decimal %q", key, raw)
	}
	return n, nil
}
