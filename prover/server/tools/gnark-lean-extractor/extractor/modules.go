package extractor

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// ModuleRule assigns every non-opaque gadget definition whose name starts with
// one of Prefixes to Module. When MaxLines is positive, a module that would
// grow past it continues in Module2, Module3, ... in definition order.
type ModuleRule struct {
	Module   string
	Prefixes []string
	MaxLines int
}

// ModuleLayout splits an extraction into Lean modules `<Root>.<name>` that
// elaborate separately. Prelude holds Order, F, Gates, named constants and the
// opaque gadgets; Circuits holds the circuit definitions; Rules place the
// gadget definitions. Every module imports Prelude and the modules defining
// the gadgets it calls; Root imports every module.
type ModuleLayout struct {
	Root     string
	Prelude  string
	Circuits string
	Rules    []ModuleRule
}

type moduleUnit struct {
	name    string
	text    string
	callees []string
}

func calleeNames(code []App) []string {
	var out []string
	for _, app := range code {
		if g, ok := app.Op.(*ExGadget); ok {
			out = append(out, g.Name)
		}
	}
	return out
}

func (l ModuleLayout) ruleFor(name string) (int, bool) {
	for i, rule := range l.Rules {
		for _, prefix := range rule.Prefixes {
			if strings.HasPrefix(name, prefix) {
				return i, true
			}
		}
	}
	return 0, false
}

// ExtractCircuitModules is ExtractCircuitsWith split into modules; it returns
// the source of each module keyed by its full module name.
func ExtractCircuitModules(opts ExportOptions, layout ModuleLayout, namespace string, field ecc.ID, circuits ...frontend.Circuit) (map[string]string, error) {
	exportMu.Lock()
	defer exportMu.Unlock()
	exportOptions, constantNames, constantValues = opts, map[string]string{}, nil
	defer func() { exportOptions, constantNames, constantValues = ExportOptions{}, nil, nil }()

	ex, err := extractCircuits(field, circuits...)
	if err != nil {
		return nil, err
	}

	// 1. Place every definition.
	moduleOf := map[string]string{}
	units := map[string][]moduleUnit{}
	var order []string
	place := func(module string, unit moduleUnit) {
		if _, ok := units[module]; !ok {
			order = append(order, module)
		}
		units[module] = append(units[module], unit)
		moduleOf[unit.name] = module
	}
	order = append(order, layout.Prelude)
	units[layout.Prelude] = nil
	shard := make([]int, len(layout.Rules))
	shardLines := make([]int, len(layout.Rules))
	for _, g := range ex.gadgets {
		text := exportGadget(g)
		if g.Opaque {
			place(layout.Prelude, moduleUnit{name: g.Name, text: text})
			continue
		}
		i, ok := layout.ruleFor(g.Name)
		if !ok {
			return nil, fmt.Errorf("no module rule for gadget %s", g.Name)
		}
		rule := layout.Rules[i]
		lines := strings.Count(text, "\n") + 1
		if rule.MaxLines > 0 && shardLines[i] > 0 && shardLines[i]+lines > rule.MaxLines {
			shard[i]++
			shardLines[i] = 0
		}
		shardLines[i] += lines
		module := rule.Module
		if shard[i] > 0 {
			module += strconv.Itoa(shard[i] + 1)
		}
		place(module, moduleUnit{name: g.Name, text: text, callees: calleeNames(g.Code)})
	}
	for _, c := range ex.circuits {
		place(layout.Circuits, moduleUnit{name: c.name, text: c.text, callees: calleeNames(c.code)})
	}

	// 2. Collect imports and order modules so every import comes first.
	imports := map[string]map[string]bool{}
	for module, list := range units {
		imports[module] = map[string]bool{}
		if module != layout.Prelude {
			imports[module][layout.Prelude] = true
		}
		for _, unit := range list {
			for _, callee := range unit.callees {
				if dep := moduleOf[callee]; dep != module {
					imports[module][dep] = true
				}
			}
		}
	}
	var sorted []string
	state := map[string]int{}
	var visit func(string) error
	visit = func(module string) error {
		switch state[module] {
		case 1:
			return fmt.Errorf("module import cycle through %s", module)
		case 2:
			return nil
		}
		state[module] = 1
		deps := make([]string, 0, len(imports[module]))
		for dep := range imports[module] {
			deps = append(deps, dep)
		}
		sort.Slice(deps, func(a, b int) bool { return indexOf(order, deps[a]) < indexOf(order, deps[b]) })
		for _, dep := range deps {
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[module] = 2
		sorted = append(sorted, module)
		return nil
	}
	for _, module := range order {
		if err := visit(module); err != nil {
			return nil, err
		}
	}

	// 3. Render the modules; constants are complete once every body is rendered.
	full := func(module string) string { return layout.Root + "." + module }
	trimmed := strings.TrimSpace(namespace)
	out := map[string]string{}
	for _, module := range sorted {
		texts := make([]string, len(units[module]))
		for i, unit := range units[module] {
			texts[i] = unit.text
		}
		body := strings.Join(texts, "\n\n")
		if module == layout.Prelude {
			out[full(module)] = fmt.Sprintf("%s\n\n%s%s\n\n%s\n", exportPrelude(namespace, field.ScalarField()), constantDeclarations(), body, exportFooter(namespace))
			continue
		}
		var header []string
		for _, dep := range sorted {
			if imports[module][dep] {
				header = append(header, "import "+full(dep))
			}
		}
		out[full(module)] = fmt.Sprintf("%s\n\nset_option linter.unusedVariables false\n\nnamespace %s\n\nvariable [Fact (Nat.Prime Order)]\n\n%s\n\n%s\n", strings.Join(header, "\n"), trimmed, body, exportFooter(namespace))
	}
	var rootImports []string
	for _, module := range sorted {
		rootImports = append(rootImports, "import "+full(module))
	}
	out[layout.Root] = strings.Join(rootImports, "\n") + "\n"
	return out, nil
}

func indexOf(list []string, item string) int {
	for i, x := range list {
		if x == item {
			return i
		}
	}
	return len(list)
}
