package abstractor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/consensys/gnark/frontend"
)

// OpaqueGadget is extracted as a Lean `opaque` predicate: the extractor never
// calls DefineGadget, so the gadget semantics enter the Lean development only
// as explicit hypotheses. OpaqueOutputs is the number of output variables; one
// output is returned as a single frontend.Variable, more as a slice.
type OpaqueGadget interface {
	GadgetDefinition
	OpaqueOutputs() int
}

// Extracting reports whether api is the Lean extractor rather than a
// constraint-system builder.
func Extracting(api frontend.API) bool {
	_, ok := api.(API)
	return ok
}

var variableType = reflect.TypeOf((*frontend.Variable)(nil)).Elem()

// IsVariableType reports whether t is frontend.Variable or a (nested) slice or
// array of it.
func IsVariableType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Interface:
		return t == variableType
	case reflect.Slice, reflect.Array:
		return IsVariableType(t.Elem())
	}
	return false
}

func isIntKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	}
	return false
}

// IsNameField reports whether an exported scalar integer field is rendered
// into gadget names (or, for opaque gadgets, as an explicit ℕ parameter).
func IsNameField(f reflect.StructField) bool {
	return f.IsExported() && isIntKind(f.Type.Kind())
}

var bigIntType = reflect.TypeOf(big.Int{})

func isHashedType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Bool:
		return true
	case reflect.Struct:
		return t == bigIntType
	case reflect.Pointer:
		return t.Elem() == bigIntType
	case reflect.Slice, reflect.Array:
		e := t.Elem()
		return isIntKind(e.Kind()) || isHashedType(e)
	}
	return false
}

func writeHashed(sb *strings.Builder, v reflect.Value) {
	switch v.Kind() {
	case reflect.Bool:
		fmt.Fprintf(sb, "%t", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprintf(sb, "%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		fmt.Fprintf(sb, "%d", v.Uint())
	case reflect.Pointer:
		if v.IsNil() {
			sb.WriteString("nil")
			return
		}
		writeHashed(sb, v.Elem())
	case reflect.Struct:
		b := v.Addr().Interface().(*big.Int)
		sb.WriteString(b.Text(10))
	case reflect.Slice, reflect.Array:
		sb.WriteString("[")
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			writeHashed(sb, v.Index(i))
		}
		sb.WriteString("]")
	}
}

// HashedGadget supplies its own name hash instead of the field encoding of
// ParamHash, for gadgets whose hash must match a key computed elsewhere. The
// hash must cover every parameter that shapes the gadget body.
type HashedGadget interface {
	GadgetHash() string
}

// ParamHash returns, for a HashedGadget, its GadgetHash; otherwise the first 8 hex digits of the SHA-256 of the gadget's
// exported parameter fields that are neither variables nor scalar integers
// (bool, big.Int, *big.Int and slices or arrays of integers or of these). The
// encoding is `Name=value;` per field in declaration order, with big integers
// in decimal, slices as `[a,b,...]` and nil pointers as `nil`. It returns ""
// when the gadget has no such field. The extractor appends `_h<hash>` to the
// gadget name, so generators keyed by ParamHash pair with the Lean definition.
// Exported fields of any other kind panic: they would silently merge distinct
// gadget bodies under one name.
func ParamHash(gadget any) string {
	if h, ok := gadget.(HashedGadget); ok {
		return h.GadgetHash()
	}
	v := reflect.Indirect(reflect.ValueOf(gadget))
	t := v.Type()
	var sb strings.Builder
	hashed := false
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() || IsVariableType(f.Type) || isIntKind(f.Type.Kind()) {
			continue
		}
		if !isHashedType(f.Type) {
			panic(fmt.Sprintf("gadget %s: exported field %s of type %s cannot be named; use a variable, integer, bool or big.Int field, or make it unexported", t.Name(), f.Name, f.Type))
		}
		hashed = true
		fv := v.Field(i)
		if !fv.CanAddr() {
			copied := reflect.New(t).Elem()
			copied.Set(v)
			fv = copied.Field(i)
		}
		fmt.Fprintf(&sb, "%s=", f.Name)
		writeHashed(&sb, fv)
		sb.WriteString(";")
	}
	if !hashed {
		return ""
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:4])
}
