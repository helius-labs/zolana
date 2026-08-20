# Indexer and prover API requests

[hurl](https://hurl.dev) request files for the two HTTP services a client talks
to: the Rings indexer (photon, JSON-RPC) and the prover server (`light-prover`).
Each file is a runnable description of part of the wire contract -- request
shape, response shape, and the errors -- so a stack can be checked without
writing a Rust test, and a witness can be replayed for latency measurements.

Nothing here starts a service. Point the files at a stack you already have:
localnet (`zolana dev start`, or the `just` recipes), the `../zolnet` compose
stack, or a deployment.

```bash
brew install hurl   # or see https://hurl.dev/docs/installation.html
```

## Running

Via `just`, which derives the URLs from the same port variables as everything
else, so `ZOLANA_PORT_OFFSET` is respected:

```bash
just hurl-indexer                 # the files that need no indexed data
just hurl-prover                  # the files that need no witness
just hurl-indexer tools/hurl/indexer/proofs.hurl --variable tree=<pool tree> --variable leaf=<utxo hash>
just hurl-prover tools/hurl/prover/prove.hurl --variable witness=fixtures/transfer-2x2.json
```

Or directly, which is what you want against a remote deployment:

```bash
hurl --test --file-root tools/hurl \
  --variables-file tools/hurl/localnet.env \
  --variable indexer_url=https://indexer.example \
  tools/hurl/indexer/health.hurl tools/hurl/indexer/sync.hurl
```

`--variable` always wins over `--variables-file`, whatever the order. Drop
`--test` to see the responses, add `--very-verbose` to see the exchange, and use
`--repeat N` to measure latency (`hurl --repeat 20 ... tools/hurl/prover/prove.hurl`
is a warm-prover benchmark once the proving key is loaded).

## Files

| File | Needs | Covers |
| --- | --- | --- |
| `indexer/health.hurl` | -- | `/liveness`, `/readiness`, `getIndexerHealth`, `getIndexerSlot` |
| `indexer/sync.hurl` | -- | the three wallet-sync queries plus `getShieldedTransactionsBySignature` |
| `indexer/errors.hurl` | -- | unknown method, invalid params, and the validation rejections |
| `indexer/proofs.hurl` | `tree`, `leaf` | `getMerkleProofs`, `getNonInclusionProofs`, `getNullifierQueueElements` |
| `prover/health.hurl` | -- | `/health`, method checks, `/metrics` |
| `prover/errors.hurl` | -- | `/prove` rejections, none of which loads a proving key |
| `prover/prove.hurl` | `witness` | `/prove` on the in-response rail |
| `prover/prove-async.hurl` | `witness`, redis | `/prove` queued, `/prove/status` polling and its rejections |
| `prover/queue.hurl` | redis (`witness` for the last entry) | `/queue/stats`, `/queue/health`, `/queue/cleanup`, `/queue/add` |

`localnet.env` holds the variables, with query keys that deliberately match
nothing so the no-input files return empty pages and assert on shape. The
variables each file needs are listed in its header comment.

"redis" means a prover started with `--redis-url`. Without one there is no
queue: `/prove` answers with the proof whatever the caller asked for, and the
queue and status paths are never registered, so the mux answers a plain 404.

## Where this maps onto a transfer

The phases `xtask loadtest` measures, and the files that cover each:

| Phase | Calls | File |
| --- | --- | --- |
| sync | `getShieldedTransactionsByTags`, `getEncryptedUtxosByTags`, `getShieldedTransactionsByNullifiers` | `indexer/sync.hurl` |
| prove | `getMerkleProofs`, `getNonInclusionProofs`, then `POST /prove` | `indexer/proofs.hurl`, `prover/prove.hurl` |
| send | Solana `sendTransaction` | not covered -- not one of these two APIs |
| confirm | `getShieldedTransactionsBySignature` | `indexer/sync.hurl` |

## Capturing a witness

A `/prove` body cannot be hand-written: every field is Poseidon-consistent with
the others, so an inconsistent one is refused by the circuit rather than by a
parser. Record a real one instead. `capture-witness.py` forwards to the prover
and writes each request body it sees:

```bash
# 1. Have a prover running on its usual port (3001 at offset 0).
# 2. Sit in front of it:
tools/hurl/capture-witness.py --listen 3101 --prover http://127.0.0.1:3001

# 3. Run anything that proves, pointed at the proxy. ZOLANA_PROVER_URL is the
#    single source of truth for the prover address, so this is all it takes:
ZOLANA_PROVER_URL=http://127.0.0.1:3101 just test-transact
```

Bodies land in `fixtures/` as `<circuitType>-<in>x<out>-<n>.json`, ready to pass
as `--variable witness=fixtures/<name>.json` with `--file-root tools/hurl`.

A witness is plaintext -- amounts, owner hashes, blindings, nullifier secrets --
so `fixtures/` is gitignored. Do not move captures anywhere that is not, and do
not capture against a wallet whose contents you would not publish.

## Auth and hosted endpoints

A prover started with `PROVER_API_KEY` set rejects everything but `/health` with
401 `unauthorized`; add `-H 'X-API-Key: <key>'` (or
`-H 'Authorization: Bearer <key>'`). A hosted indexer that authenticates with an
`api-key` query parameter needs it on the URL, so set `indexer_url` to the base
and append the parameter per entry, or terminate auth in front of hurl.
