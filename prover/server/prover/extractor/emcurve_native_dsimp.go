package extractor

import (
	"fmt"
	"regexp"
	"strings"
)

// nativeDsimpDefinition records the exact emitted native local definition.
// It changes only the whitelist used by ordinary Lean dsimp commands.
type nativeDsimpDefinition struct {
	name string
	body string
}

var nativeDsimpReference = regexp.MustCompile(`\bgate_[0-9]+\b`)
var nativeDsimpName = regexp.MustCompile(`^gate_[0-9]+$`)

// largeFlagNativeDsimp deliberately limits the initial application. Previously
// checked small predicates keep byte-identical proof source.
func largeFlagNativeDsimp(name string) bool {
	switch name {
	case "CheckPolynomial_49_h8696e642", "CheckPolynomial_49_h8f49f727",
		"CheckPolynomial_49_h9104a5ae", "CheckPolynomial_49_ha68a8775":
		return true
	default:
		return false
	}
}

// nativeDsimpClosure validates every recorded definition, including unused
// definitions, before selecting the transitive dependencies of the comparison.
// Missing, duplicated, forward and cyclic dependencies fail rather than being
// silently omitted. The result retains source order.
func nativeDsimpClosure(definitions []nativeDsimpDefinition, roots []string) ([]string, error) {
	indices := make(map[string]int, len(definitions))
	for i, d := range definitions {
		if !nativeDsimpName.MatchString(d.name) || strings.TrimSpace(d.body) == "" {
			return nil, fmt.Errorf("malformed native dsimp definition %q", d.name)
		}
		if _, duplicate := indices[d.name]; duplicate {
			return nil, fmt.Errorf("duplicate native dsimp definition %s", d.name)
		}
		indices[d.name] = i
	}
	dependencies := make([][]int, len(definitions))
	for i, d := range definitions {
		for _, name := range nativeDsimpReference.FindAllString(d.body, -1) {
			j, exists := indices[name]
			if !exists {
				return nil, fmt.Errorf("%s references missing native definition %s", d.name, name)
			}
			dependencies[i] = append(dependencies[i], j)
		}
	}
	state := make([]uint8, len(definitions))
	var validate func(int) error
	validate = func(i int) error {
		if state[i] == 1 {
			return fmt.Errorf("cyclic native dsimp dependency at %s", definitions[i].name)
		}
		if state[i] == 2 {
			return nil
		}
		state[i] = 1
		for _, j := range dependencies[i] {
			if err := validate(j); err != nil {
				return err
			}
		}
		state[i] = 2
		return nil
	}
	for i := range definitions {
		if err := validate(i); err != nil {
			return nil, err
		}
		for _, j := range dependencies[i] {
			if j >= i {
				return nil, fmt.Errorf("%s has a forward native dependency %s", definitions[i].name, definitions[j].name)
			}
		}
	}
	selected := make([]bool, len(definitions))
	var selectDependency func(int)
	selectDependency = func(i int) {
		if selected[i] {
			return
		}
		selected[i] = true
		for _, j := range dependencies[i] {
			selectDependency(j)
		}
	}
	for _, root := range roots {
		for _, name := range nativeDsimpReference.FindAllString(root, -1) {
			i, exists := indices[name]
			if !exists {
				return nil, fmt.Errorf("comparison references missing native definition %s", name)
			}
			selectDependency(i)
		}
	}
	var result []string
	for i, d := range definitions {
		if selected[i] {
			result = append(result, d.name)
		}
	}
	return result, nil
}

// emitFlagNativeDsimp unfolds the exact same native values using their
// dependency closure. Earlier definitions are dependencies of later ones, so
// the chunks run from the latest source interval to the earliest. Every alias
// and model let is preserved in every command; no command exceeds 200 names.
// This is proof-source emission, not a new Lean tactic or a proof bypass.
func emitFlagNativeDsimp(w *instanceWriter, indent string,
	definitions []nativeDsimpDefinition, roots, aliases, modelLets []string) error {
	names, err := nativeDsimpClosure(definitions, roots)
	if err != nil {
		return err
	}
	var extras []string
	seen := make(map[string]bool)
	for _, name := range append(append([]string{}, aliases...), modelLets...) {
		if name == "" {
			return fmt.Errorf("empty native dsimp alias or model let")
		}
		if !seen[name] {
			seen[name] = true
			extras = append(extras, name)
		}
	}
	capacity := 200 - len(extras)
	if capacity <= 0 {
		return fmt.Errorf("native dsimp aliases/model lets exhaust the 200-name limit")
	}
	if len(names) == 0 {
		w.line("%sdsimp only [%s]", indent, strings.Join(extras, ", "))
		return nil
	}
	for end := len(names); end > 0; {
		start := end - capacity
		if start < 0 {
			start = 0
		}
		chunk := append(append([]string{}, names[start:end]...), extras...)
		w.line("%sdsimp only [%s]", indent, strings.Join(chunk, ", "))
		end = start
	}
	return nil
}
