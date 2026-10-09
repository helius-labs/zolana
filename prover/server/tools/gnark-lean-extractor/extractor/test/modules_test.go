package extractor_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

func TestModuleCircuits(t *testing.T) {
	layout := extractor.ModuleLayout{
		Root:     "Mods.Circuit",
		Prelude:  "Prelude",
		Circuits: "Top",
		Rules: []extractor.ModuleRule{
			{Module: "Hints", Prefixes: []string{"HintGadget"}},
			{Module: "Scale", Prefixes: []string{"ScaleGadget"}, MaxLines: 4},
		},
	}
	modules, err := extractor.ExtractCircuitModules(extractor.ExportOptions{}, layout, "ModuleCircuits", ecc.BN254, &HintCircuit{}, &ScaleCircuit{}, &OpaqueCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	want := []string{"Mods.Circuit", "Mods.Circuit.Hints", "Mods.Circuit.Prelude", "Mods.Circuit.Scale", "Mods.Circuit.Scale2", "Mods.Circuit.Scale3", "Mods.Circuit.Top"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("modules %v, want %v", names, want)
	}
	var out strings.Builder
	for _, name := range names {
		out.WriteString("-- module " + name + "\n" + modules[name] + "\n")
	}
	checkOutput(t, out.String())
}

func TestModuleWithoutRule(t *testing.T) {
	layout := extractor.ModuleLayout{Root: "Mods", Prelude: "Prelude", Circuits: "Top"}
	if _, err := extractor.ExtractCircuitModules(extractor.ExportOptions{}, layout, "ModuleCircuits", ecc.BN254, &HintCircuit{}); err == nil {
		t.Fatal("a gadget without a module rule must be rejected")
	}
}
