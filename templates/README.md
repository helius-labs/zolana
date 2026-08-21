# Custom ring template

`templates/custom-ring` is a cargo-generate template. One run produces one ring
repository, a workspace with the ring program at a fresh program id and an
operator CLI, pinned to the Zolana revision the wizard ran from.

## Running the wizard

From a Zolana checkout run `just ring-new`, optionally with a destination
directory. The wizard creates the program keypair, asks for the authority
keypair, the service URLs and the features, records every answer in the ring's
`ring.toml`, and moves the keypair into the ring's `keys/`. `RING_NAME` skips
the name prompt, `--silent` answers every question with its default and is
how CI runs it, for example `RING_NAME=demo just ring-new /tmp --silent`.
Extra arguments reach `cargo generate`, so any answer can be given as
`-d name=value`. `CUSTOM_RING_AUTHORITY_KEYPAIR` replaces the authority path
without a prompt.

The localnet URLs the wizard records follow this checkout's `ZOLANA_PORT_OFFSET`,
so a ring generated from an offset clone talks to that clone's validator.

## The pinned source

A generated ring does not vendor Zolana. Its `Cargo.toml` points the program and
the CLI at `{{zolana_path}}/custom-rings`, by default `.zolana` inside the
ring. `just source`, a dependency of every build recipe, clones the recorded
repository there and checks out the recorded revision, so a fresh checkout of
the ring builds against the same commit it was generated from. The recipe
refuses to touch `.zolana` when it is a symlink or holds a symlinked `.git`.

For local development pass `RING_ZOLANA_PATH=checkout` to `just ring-new`.
The ring then uses this checkout in place, nothing is cloned and `just source`
is a no-op, and edits under `custom-rings/` are picked up on the next build.

## Secrets

`.env` holds the Helius API key, the ring RPC origins and the prover's Redis
URL, `keys/` holds the program keypair and the auditor key. Both are ignored by
git. Keep them in the deployment secret store, a fresh checkout mounts them
through `CUSTOM_RING_PROGRAM_KEYPAIR_FILE` and `CUSTOM_RING_AUDITOR_KEY_FILE`
before its first `just pipeline`.

The generated `README.md` is the operator's guide to the ring itself.
