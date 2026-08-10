module circuits

go 1.25.7

require (
	github.com/consensys/gnark v0.15.0
	github.com/consensys/gnark-crypto v0.20.1
	zolana/prover v0.0.0
)

require (
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/google/pprof v0.0.0-20260202012954-cb029daf43ef // indirect
	github.com/iden3/go-iden3-crypto v0.0.17 // indirect
	github.com/ingonyama-zk/icicle-gnark/v3 v3.2.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/reilabs/gnark-lean-extractor/v3 v3.0.0 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	helios.local/witgen v0.0.0-00010101000000-000000000000 // indirect
)

replace zolana/prover => ../../../../prover/server

replace github.com/reilabs/gnark-lean-extractor/v3 => github.com/Lightprotocol/gnark-lean-extractor/v3 v3.0.0-20250920122823-aa0219463107

// The same gnark fork the prover server pins. Needed because zolana/prover's
// replace directives do not apply here and the aggregate circuit uses the
// fork's verifier options.
replace github.com/consensys/gnark => github.com/Atamanov/gnark v0.15.1-0.20260806151717-c61526a9bfd8

// Module resolution walks zolana/prover's test imports, so these must resolve
// even though no code here uses them. Both are unpublished and resolve only
// beside a checkout of this repository.

replace helios.local/witgen => ../../../../../witgen

replace github.com/ingonyama-zk/icicle-gnark/v3 => ../../../../../icicle-gnark
