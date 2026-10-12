package request

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	merge "github.com/helius-labs/zolana/prover/server/prover/merge"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa_only"
)

// MaxBodyBytes bounds a body ParseStrict reads; the largest merge is under 1 MiB.
const MaxBodyBytes = 8 << 20

// ParseStrict is Parse for a prover built against one client release. The body
// must spell out exactly its circuit's fields, each once and with a value,
// since an absent value would otherwise prove as zero; its shape must be one
// the circuit supports, and its key one that exists.
func ParseStrict(body []byte) (*Request, error) {
	if len(body) > MaxBodyBytes {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", ErrMalformed, MaxBodyBytes)
	}
	var envelope struct {
		CircuitType common.CircuitType `json:"circuitType"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	var schema reflect.Type
	switch envelope.CircuitType {
	case common.TransferConfidentialCircuitType, common.TransferRingCircuitType, common.TransferRingAuthorityCircuitType:
		schema = reflect.TypeOf(transfer.TransferParametersJSON{})
	case common.MergeCircuitType, common.MergeRingCircuitType:
		schema = reflect.TypeOf(merge.MergeParametersJSON{})
	default:
		return nil, fmt.Errorf("%w: circuit type %q", ErrUnsupported, envelope.CircuitType)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := exactly(decoder, schema, 0); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: data after the body", ErrMalformed)
	}
	request, err := Parse(body)
	if err != nil {
		return nil, err
	}
	if err := request.params.ValidateShape(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if request.KeyFile == "" {
		return nil, fmt.Errorf("%w: no %s key for %dx%d", ErrUnsupported, request.Circuit, request.Inputs, request.Outputs)
	}
	return request, nil
}

// exactly reads one JSON value of type expected: every struct field present
// once and no other, strings non-empty, numbers unsigned 32-bit integers.
func exactly(decoder *json.Decoder, expected reflect.Type, depth int) error {
	if depth > 32 {
		return fmt.Errorf("nested too deeply")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("null value")
	}
	switch expected.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return fmt.Errorf("expected an object")
		}
		fields := make(map[string]reflect.Type)
		jsonFields(expected, fields)
		seen := make(map[string]bool, len(fields))
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			name, _ := token.(string)
			field, known := fields[name]
			if !known {
				return fmt.Errorf("unknown field %q", name)
			}
			if seen[name] {
				return fmt.Errorf("repeated field %q", name)
			}
			seen[name] = true
			if err := exactly(decoder, field, depth+1); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		if _, err := decoder.Token(); err != nil {
			return err
		}
		for name := range fields {
			if !seen[name] {
				return fmt.Errorf("missing field %q", name)
			}
		}
	case reflect.Slice:
		if token != json.Delim('[') {
			return fmt.Errorf("expected an array")
		}
		for decoder.More() {
			if err := exactly(decoder, expected.Elem(), depth+1); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return err
		}
	case reflect.String:
		value, ok := token.(string)
		if !ok || value == "" || len(value) > 256 {
			return fmt.Errorf("expected a non-empty string")
		}
	case reflect.Uint32:
		number, ok := token.(json.Number)
		if !ok {
			return fmt.Errorf("expected a number")
		}
		if _, err := strconv.ParseUint(number.String(), 10, 32); err != nil {
			return fmt.Errorf("expected an unsigned 32-bit integer")
		}
	default:
		return fmt.Errorf("unexpected schema kind %s", expected.Kind())
	}
	return nil
}

// jsonFields maps each JSON key of a struct to its type, promoting the fields
// of an untagged embedded struct as encoding/json does.
func jsonFields(expected reflect.Type, fields map[string]reflect.Type) {
	for index := 0; index < expected.NumField(); index++ {
		field := expected.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if field.Anonymous && name == "" && field.Type.Kind() == reflect.Struct {
			jsonFields(field.Type, fields)
			continue
		}
		if name == "-" || !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
}
