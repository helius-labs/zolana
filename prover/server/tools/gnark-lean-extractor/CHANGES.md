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
