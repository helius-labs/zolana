module circuits

go 1.25.7

require (
	github.com/consensys/gnark v0.16.3
	github.com/consensys/gnark-crypto v0.21.0
	zolana/prover v0.0.0
)

require (
	github.com/bits-and-blooms/bitset v1.24.6 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3 // indirect
	github.com/iden3/go-iden3-crypto v0.0.17 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/reilabs/gnark-lean-extractor/v3 v3.0.0 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace zolana/prover => ../../../../prover/server

replace github.com/reilabs/gnark-lean-extractor/v3 => github.com/Lightprotocol/gnark-lean-extractor/v3 v3.0.0-20250920122823-aa0219463107
