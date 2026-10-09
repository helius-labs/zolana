package extractor

import (
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// ExportOptions select Lean output forms that keep large extractions cheap to
// elaborate. The zero value reproduces the original output byte for byte.
type ExportOptions struct {
	// VectorGet renders vector access as `(xs.get (i : Fin n))` instead of
	// `xs[i]`; the index is a literal of the vector's own Fin type, so no
	// bound-proof tactic runs. Both forms are definitionally equal.
	VectorGet bool
	// MaxBodyApps, when positive, splits a definition body of more operations
	// than this into a chain of part definitions `<Name>_p<j>`. Each part
	// takes the definition's arguments, the gate variables still needed
	// downstream and the continuation, and ends by calling the next part, so
	// no single term nests more than MaxBodyApps binders. Unfolding the parts
	// gives back the unsplit body.
	MaxBodyApps int
	// NamedConstantDigits, when positive, replaces every constant of at least
	// this many decimal digits by an abbreviation `K_<i>` (numbered in order
	// of first use) declared after the prelude.
	NamedConstantDigits int
}

var (
	exportMu       sync.Mutex
	exportOptions  ExportOptions
	constantNames  map[string]string
	constantValues []string
)

// ExtractCircuitsWith is ExtractCircuits with the given output options.
func ExtractCircuitsWith(opts ExportOptions, namespace string, field ecc.ID, circuits ...frontend.Circuit) (string, error) {
	exportMu.Lock()
	defer exportMu.Unlock()
	exportOptions, constantNames, constantValues = opts, map[string]string{}, nil
	defer func() { exportOptions, constantNames, constantValues = ExportOptions{}, nil, nil }()
	return ExtractCircuits(namespace, field, circuits...)
}

func constantExpr(value string) string {
	if exportOptions.NamedConstantDigits <= 0 || len(value) < exportOptions.NamedConstantDigits {
		return fmt.Sprintf("(%s:F)", value)
	}
	name, ok := constantNames[value]
	if !ok {
		name = fmt.Sprintf("K_%d", len(constantValues))
		constantNames[value] = name
		constantValues = append(constantValues, value)
	}
	return name
}

// constantDeclarations declares the named constants; empty without any.
func constantDeclarations() string {
	if len(constantValues) == 0 {
		return ""
	}
	decls := make([]string, len(constantValues))
	for i, v := range constantValues {
		decls[i] = fmt.Sprintf("abbrev K_%d : F := %s", i, v)
	}
	return strings.Join(decls, "\n") + "\n\n"
}

func vectorAccess(base string, index, size int) string {
	if exportOptions.VectorGet {
		return fmt.Sprintf("(%s.get (%d : Fin %d))", base, index, size)
	}
	return fmt.Sprintf("%s[%d]", base, index)
}

func splitBody(code []App) bool {
	return exportOptions.MaxBodyApps > 0 && len(code) > exportOptions.MaxBodyApps
}

// gateType is the Lean type of the variable an operation binds.
func gateType(app App) string {
	switch op := app.Op.(type) {
	case OpHint:
		return fmt.Sprintf("List.Vector F %d", op.NbOutputs)
	case *ExGadget:
		if len(op.OutputsFlat) == 1 {
			return "F"
		}
		return genKTypeSignature(reflect.ValueOf(op.Outputs))
	case OpKind:
		if op == OpToBinary {
			return fmt.Sprintf("List.Vector F %s", app.Args[1].(Integer).Value.Text(10))
		}
	}
	return "F"
}

func gateUses(args []Operand) []int {
	var out []int
	for _, arg := range args {
		for _, base := range extractGateVars(arg) {
			if g, ok := base.(Gate); ok {
				out = append(out, g.Index)
			}
		}
	}
	return out
}

// genSplitDef renders a definition whose body is split into parts. header
// renders the signature of a definition named name with extra binders
// inserted before the continuation.
func genSplitDef(name string, header func(name, extra string) string, inAssignment []ExArg, code []App, outputs []Operand, hasK bool, finalLine func(gateVars []string) string) string {
	gateVars := assignGateVars(code, outputs...)
	lines := make([]string, len(code))
	lastUse := make([]int, len(code))
	for i := range lastUse {
		lastUse[i] = -1
	}
	for i, app := range code {
		lines[i] = genLine(app, gateVars[i], inAssignment, gateVars)
		for _, g := range gateUses(app.Args) {
			lastUse[g] = max(lastUse[g], i)
		}
	}
	for _, g := range gateUses(outputs) {
		lastUse[g] = len(code)
	}
	live := func(start int) []int {
		var out []int
		for g := 0; g < start; g++ {
			if gateVars[g] != "" && lastUse[g] >= start {
				out = append(out, g)
			}
		}
		return out
	}
	inputs := make([]string, len(inAssignment))
	for i, in := range inAssignment {
		inputs[i] = in.Name
	}
	call := func(part, start int) string {
		args := append([]string{}, inputs...)
		for _, g := range live(start) {
			args = append(args, gateVars[g])
		}
		if hasK {
			args = append(args, "k")
		}
		return fmt.Sprintf("    %s_p%d %s", name, part, strings.Join(args, " "))
	}
	size := exportOptions.MaxBodyApps
	var defs []string
	for part := (len(code) - 1) / size; part >= 1; part-- {
		start := part * size
		end := min(start+size, len(code))
		var params []string
		for _, g := range live(start) {
			params = append(params, fmt.Sprintf("(%s: %s)", gateVars[g], gateType(code[g])))
		}
		tail := finalLine(gateVars)
		if end < len(code) {
			tail = call(part+1, end)
		}
		body := strings.Join(lines[start:end], "") + tail
		defs = append(defs, fmt.Sprintf("%s\n%s", header(fmt.Sprintf("%s_p%d", name, part), strings.Join(params, " ")), body))
	}
	tail := finalLine(gateVars)
	if size < len(code) {
		tail = call(1, size)
	}
	main := fmt.Sprintf("%s\n%s", header(name, ""), strings.Join(lines[:min(size, len(code))], "")+tail)
	// Parts are emitted last first: each part calls the one after it.
	return strings.Join(append(defs, main), "\n\n")
}

func gadgetFinalLine(inAssignment []ExArg, outputs []Operand) func([]string) string {
	return func(gateVars []string) string {
		switch len(outputs) {
		case 0:
			return "    True"
		case 1:
			return fmt.Sprintf("    k %s", operandExpr(outputs[0], inAssignment, gateVars))
		default:
			return fmt.Sprintf("    k %s", operandExpr(ProjArray{outputs}, inAssignment, gateVars))
		}
	}
}

func circuitFinalLine([]string) string {
	return "    True"
}

func joinBinders(binders ...string) string {
	var nonEmpty []string
	for _, b := range binders {
		if b != "" {
			nonEmpty = append(nonEmpty, b)
		}
	}
	return strings.Join(nonEmpty, " ")
}
