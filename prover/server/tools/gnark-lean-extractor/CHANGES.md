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
- Constant gadget outputs (an `int` or `*big.Int` in the returned slice) are
  passed through the continuation like any other output instead of panicking.
