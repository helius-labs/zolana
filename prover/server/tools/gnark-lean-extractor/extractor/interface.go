// This file contains the public API for running the extractor.
package extractor

import (
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"slices"
)

// CircuitToLeanWithName exports a `circuit` to Lean over a `field` with `namespace`
// CircuitToLeanWithName and CircuitToLean aren't joined in a single function
// CircuitToLean(circuit abstractor.Circuit, field ecc.ID, namespace ...string) because the long term view
// is to add an optional parameter to support custom `set_option` directives in the header.
func CircuitToLeanWithName(circuit frontend.Circuit, field ecc.ID, namespace string) (out string, err error) {
	schema, err := getSchema(circuit, field.ScalarField())
	if err != nil {
		return "", err
	}

	inputs := circuitInit(circuit, schema)

	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	err = circuit.Define(&api)
	if err != nil {
		return "", err
	}

	extractorCircuit := ExCircuit{
		Inputs:  inputs,
		Gadgets: api.Gadgets,
		Code:    api.Code,
		Field:   api.FieldID,
	}
	out = exportCircuit(extractorCircuit, namespace)
	return out, nil
}

// CircuitToLean exports a `circuit` to Lean over a `field` with the namespace being the
// struct name of `circuit`
// When the namespace argument is not defined, it uses the name of the struct circuit
func CircuitToLean(circuit frontend.Circuit, field ecc.ID) (string, error) {
	name := getStructName(circuit)
	return CircuitToLeanWithName(circuit, field, name)
}

// GadgetToLeanWithName exports a `gadget` to Lean over a `field` with `namespace`
// Same notes written for CircuitToLeanWithName apply to GadgetToLeanWithName and GadgetToLean
func GadgetToLeanWithName(gadget abstractor.GadgetDefinition, field ecc.ID, namespace string) (out string, err error) {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	api.DefineGadget(gadget)
	gadgets := exportGadgets(api.Gadgets)
	prelude := exportPrelude(namespace, api.FieldID.ScalarField())
	footer := exportFooter(namespace)
	return fmt.Sprintf("%s\n\n%s\n\n%s", prelude, gadgets, footer), nil
}

// GadgetToLean exports a `gadget` to Lean over a `field`
func GadgetToLean(gadget abstractor.GadgetDefinition, field ecc.ID) (string, error) {
	name := getStructName(gadget)
	return GadgetToLeanWithName(gadget, field, name)
}

// ExtractCircuits is used to export a series of `circuits` to Lean over a `field` under `namespace`.
func ExtractCircuits(namespace string, field ecc.ID, circuits ...frontend.Circuit) (out string, err error) {
	ex, err := extractCircuits(field, circuits...)
	if err != nil {
		return "", err
	}
	circuits_extracted := make([]string, len(ex.circuits))
	for i, c := range ex.circuits {
		circuits_extracted[i] = c.text
	}

	prelude := exportPrelude(namespace, field.ScalarField())
	gadgets := exportGadgets(ex.gadgets)
	footer := exportFooter(namespace)
	return fmt.Sprintf("%s\n\n%s%s\n\n%s\n\n%s", prelude, constantDeclarations(), gadgets, strings.Join(circuits_extracted, "\n\n"), footer), nil
}

type extractedCircuit struct {
	name string
	text string
	code []App
}

type extraction struct {
	gadgets  []ExGadget
	circuits []extractedCircuit
}

// extractCircuits runs every circuit through one extractor, so gadgets shared
// between circuits are defined once, and renders each circuit definition.
func extractCircuits(field ecc.ID, circuits ...frontend.Circuit) (*extraction, error) {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	var out extraction
	var past_circuits []string

	for _, circuit := range circuits {
		schema, err := getSchema(circuit, field.ScalarField())
		if err != nil {
			return nil, err
		}
		args := circuitInit(circuit, schema)

		name := generateUniqueName(circuit, args, circuitName)
		if slices.Contains(past_circuits, name) {
			continue
		}
		past_circuits = append(past_circuits, name)

		api.store = nil
		err = circuit.Define(&api)
		if err != nil {
			return nil, err
		}

		extractorCircuit := ExCircuit{Inputs: args, Code: api.Code, Field: api.FieldID}
		circ := fmt.Sprintf("def %s %s: Prop :=\n%s", name, genArgs(extractorCircuit.Inputs), genCircuitBody(extractorCircuit))
		if splitBody(extractorCircuit.Code) {
			inputs := extractorCircuit.Inputs
			header := func(name, extra string) string {
				return fmt.Sprintf("def %s %s: Prop :=", name, joinBinders(genArgs(inputs), extra))
			}
			circ = genSplitDef(name, header, inputs, extractorCircuit.Code, nil, false, circuitFinalLine)
		}
		out.circuits = append(out.circuits, extractedCircuit{name: name, text: circ, code: api.Code})
		api.Code = []App{}
	}
	out.gadgets = api.Gadgets
	return &out, nil
}

// ExtractGadgets is used to export a series of `gadgets` to Lean over a `field` under `namespace`.
func ExtractGadgets(namespace string, field ecc.ID, gadgets ...abstractor.GadgetDefinition) (out string, err error) {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	for _, gadget := range gadgets {
		api.DefineGadget(gadget)
	}

	gadgets_string := exportGadgets(api.Gadgets)
	prelude := exportPrelude(namespace, api.FieldID.ScalarField())
	footer := exportFooter(namespace)
	return fmt.Sprintf("%s\n\n%s\n\n%s", prelude, gadgets_string, footer), nil
}
