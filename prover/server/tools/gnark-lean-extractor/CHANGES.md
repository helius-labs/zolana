# Local changes

Vendored from `github.com/Lightprotocol/gnark-lean-extractor/v3`
`v3.0.0-20250920122823-aa0219463107` (a fork of `reilabs/gnark-lean-extractor`).
The module path stays `github.com/reilabs/gnark-lean-extractor/v3`; the prover
module points at this directory with a `replace` directive.

## Dependencies

- Requires `github.com/consensys/gnark v0.16.4` and the `gnark-crypto` pin of
  the prover module.
- `extractor/interface.go` imports the standard library `slices` instead of
  `golang.org/x/exp/slices`.

## Extraction of hint-, lookup- and commitment-based circuits

- Hints (`NewHint`, `Compiler().NewHint`, `NewHintForId`) extract as free
  existential binders, always vector-typed and annotated with the hint name:
  `∃gate_7 : List.Vector F 17, -- hint <name>`. No equation is recorded: a
  hint output is unconstrained.
- `Compiler().Defer` callbacks are recorded in `CodeExtractor.Deferred` and
  never run. Gate indices are scoped per gadget, so hoisting a callback to the
  end of the circuit is not possible. Commitment-based arguments that live in
  deferred callbacks must be replaced by opaque gadgets in extraction.
- `abstractor.OpaqueGadget` (`OpaqueOutputs() int`) extracts as a Lean
  `opaque` predicate; `DefineGadget` is never called. Exported integer fields
  become explicit `ℕ` parameters instead of name suffixes. One output is a
  single `F` continuation, more outputs a `List.Vector F n` continuation.
  `abstractor.Extracting(api)` selects extraction-only code paths.
- `CodeExtractor` implements the `SetKeyValue`/`GetKeyValue` store, reset
  before each circuit in `ExtractCircuits`.
- Gadget names hash exported `bool`, `big.Int`, `*big.Int` and slice or array
  of integer or such fields into a `_h<8 hex>` suffix (`abstractor.ParamHash`);
  any other exported non-variable field kind panics. Unexported fields are
  ignored for naming, arguments and cloning. `cloneGadget` deep-copies
  `big.Int` values, and `ExGadget.Call` passes only exported variable fields.
- `MustBeLessOrEqCst` mirrors gnark's R1CS builder with public operations, so
  `bits.ToBinary` with the native-modulus reducedness check extracts.
- `*big.Int` constants are copied when recorded; callers that mutate a
  `*big.Int` after passing it to the API (gnark `bits.ToBinary` does) no longer
  alias every recorded constant.
- `TestAnotherCircuit.lean` now carries the parameter hash of its `[2]int`
  fields.
- A gadget implementing `abstractor.HashedGadget` (`GadgetHash() string`)
  supplies its own name hash, so a key computed elsewhere (certificate
  records) pairs with the Lean definition name.
- `ExtractCircuitsWith(ExportOptions{...}, ...)` selects output forms for
  large extractions; the zero value and `ExtractCircuits` keep the original
  output byte for byte. `VectorGet` renders `(xs.get (i : Fin n))` instead of
  `xs[i]`, which avoids one bound-proof tactic per access (about 9x faster
  elaboration on emulated-field checks). `MaxBodyApps` splits longer bodies
  into continuation parts `<Name>_p<j>` (emitted last part first) taking the
  definition's arguments, the live gate variables and `k`; deeply nested
  bodies otherwise exceed `maxRecDepth` and parse in superlinear time.
  `NamedConstantDigits` replaces constants of at least that many digits by
  `abbrev K_<i> : F := <value>` declarations after the prelude, numbered in
  order of first use. `SeedConstants` fixes the numbering of known constants
  (value i is `K_i`, declared even if unused); new constants continue after
  them, so adding circuits never renumbers existing names.
- `ExtractCircuitModules(opts, ModuleLayout{...}, ...)` splits an extraction
  into Lean modules `<Root>.<name>` that elaborate separately: a prelude
  module (Order, F, Gates, named constants, opaque gadgets), modules assigned
  by gadget-name prefix rules (split at `MaxLines` in definition order), a
  module of circuit definitions, and the root module importing all of them.
  Each module imports the prelude and the modules defining the gadgets it
  calls; an unassigned gadget or an import cycle is an error.
- Fix (soundness of the extracted relation, inherited from upstream): an
  Add, Sub or Mul with more than two operands was emitted as a chain that
  rebound the same gate name per link, `∃g, g = add a b ∧ ∃g, g = add g c`,
  where the second `g` on the right refers to its own binder and forces
  `c = 0`. It is now one binder over a left-nested expression,
  `∃g, g = add (add a b) c`. Two-operand gates print as before; gate
  numbering is unchanged. The goldens of TestToBinaryCircuit,
  TestExtractCircuits, TestSplitCircuit and TestNestedOutputCircuit change
  only on those lines.
- Fix: a gadget output nested two or more levels deep whose element is a bare
  gate or input (not a projection) was returned to the caller as the whole
  gadget result, dropping its indices. Every level is now projected.
- Fix: a gadget returning a one-element slice was typed `k : F -> Prop` while
  its callers index the result; it is now `k : List.Vector F 1 -> Prop`.
  Only a gadget returning a bare variable has a scalar continuation.
- Constant gadget outputs (an `int` or `*big.Int` in the returned slice) are
  passed through the continuation like any other output instead of panicking.
