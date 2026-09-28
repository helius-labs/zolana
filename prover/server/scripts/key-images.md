# BN254 proving-key memory images

The prover's `.key` files store the Groth16 proving key with gnark's
`WriteDump`/`ReadDump`: native Montgomery-form point arrays, including Pedersen
commitment bases. Transfer/merge and batch headers, verifying keys, and
constraint systems retain their existing encoding. A format fingerprint pins
the gnark and gnark-crypto versions. Images support amd64 and arm64; both have
the same little-endian uint64 point layout. Other architectures fail explicitly.

The existing lockfile SHA256 and size checks authenticate the distributed file
before the lazy loader decodes it. No additional checksum file or local cache is
needed. `ReadSystemFromFile` also reports the hash of the file it actually read,
as before. Direct low-level readers accept trusted local files only: dump
lengths and point arrays are not validated by gnark.

## Reproduce the conversion without publishing

From the repository root:

```sh
go build -C prover/server -o ../../target/convert-key-image ./cmd/convert-key-image
python3 prover/server/scripts/convert_key_images.py target/key-images \
  --converter target/convert-key-image \
  --expected-lock prover/server/prover/provingkeys/proving-keys.lock
```

The script downloads the old artifacts pinned in `key-image-source.lock`, checks
their original hashes, and converts them without generating new setup randomness.
The converter reconstructs each complete original file from its image and checks
its original hash again, proving that every point, domain value, infinity map,
commitment basis, verifying key, and constraint byte survived the conversion.
The final image hash must match the new lockfile. Source files stay under
`target/key-images/compressed-source`; the distributable images are the top-level
`.key` files. Optional positional filenames restrict the operation to a subset.

For local proving tests, use the converted directory as `prover/server/proving-keys`
(or copy the top-level `.key` files there). Do not overwrite unrelated local keys.

```sh
go test -C prover/server ./prover/... ./cmd/... -timeout 30m
ZOLANA_KEY_IMAGE_BENCH_DIR="$PWD/target/key-images" \
  go test -C prover/server ./prover/common -run '^$' \
  -bench 'Benchmark(ProvingKeyLoad|PublishedSystemLoad)' -benchtime=5x -count=3
```

The first benchmark measures PK decoding in memory; the second includes file I/O,
SHA256, VK and constraint decoding using real published keys and the OS page cache.
Images use more disk and transfer bytes than compressed keys. The server still
loads lazily and keeps a loaded key in memory.

## Publication remains a separate step

This migration does not publish artifacts. Before deploying this revision or
running integration CI that downloads its keys, publish the converted top-level
`.key` files into the new immutable object-store prefix in `proving-keys.lock`,
and publish the six `source: release` ring files as `custom-ring-keys-v15`.
Keep the previous prefix and release untouched. Publish existing converted keys;
do not run setup or the key-rotation script. The new checksums are embedded in
Rust programs and the TypeScript SDK, so roll those out with the prover revision.

Until publication, CI/local environments can run the conversion command above
to populate the expected keys without changing or bypassing their checksums.
When upgrading gnark or gnark-crypto, explicitly migrate the image format and
repin the resulting artifacts; the dependency test prevents accidental reuse.
