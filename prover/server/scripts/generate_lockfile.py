#!/usr/bin/env python3
"""Generate proving-keys.lock: the committed manifest that pins every proving
key's content hash and size.

The lockfile IS the proving-key version. It records the object-store `prefix`
(`<base-prefix>/<version-hash>`, where the version hash is derived from the whole
key set) and maps each `*.key` filename to its sha256 and byte size. The
downloader fetches `<base-url>/<prefix>/<name>` and hard-fails unless the bytes
hash to the pinned value, so proving-key <-> verifying-key <-> code drift is
impossible (the lock changes in the same commit as the regenerated verifying
keys). The version-hashed prefix is immutable per key set: rotating keys yields a
NEW prefix/folder, so an already-published CLI keeps fetching its own (unchanged)
folder while a new CLI uses the new one -- and human-readable filenames are
preserved within each version folder.

Usage:
    generate_lockfile.py <keys-dir> [--out <lockfile>] [--prefix <base-prefix>]

Defaults: keys-dir positional,
out=prover/server/prover/provingkeys/proving-keys.lock (the file the Go
`provingkeys` package embeds), base-prefix=proving-keys (a `/<version-hash>`
segment is appended). Only `*.key` files are included (CHECKSUM and tooling are
not distributed by the downloader).
"""
import argparse
import hashlib
import json
import os
import sys

CHUNK = 1024 * 1024


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate proving-keys.lock")
    parser.add_argument("keys_dir", help="directory holding the *.key files")
    parser.add_argument("--out", default=None, help="output lockfile path")
    parser.add_argument(
        "--prefix",
        default="proving-keys",
        help="object key prefix under the distribution base URL",
    )
    args = parser.parse_args()

    keys_dir = os.path.abspath(args.keys_dir)
    if not os.path.isdir(keys_dir):
        print(f"not a directory: {keys_dir}", file=sys.stderr)
        return 1
    # Default output is the file the Go downloader embeds (//go:embed), derived
    # from this script's location so it is independent of the caller's cwd.
    default_out = os.path.normpath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "prover",
            "provingkeys",
            "proving-keys.lock",
        )
    )
    out = args.out or default_out

    names = sorted(n for n in os.listdir(keys_dir) if n.endswith(".key"))
    if not names:
        print(f"no *.key files in {keys_dir}", file=sys.stderr)
        return 1

    keys = {}
    for name in names:
        path = os.path.join(keys_dir, name)
        size = os.path.getsize(path)
        digest = sha256_file(path)
        keys[name] = {"sha256": digest, "size": size}
        print(f"  {name}  {size}  {digest}", file=sys.stderr)

    # The version hash is derived from the key set (each name + its sha256), so it
    # changes iff any key changes. It names an immutable per-version folder under
    # the base prefix: rotating keys produces a new folder, leaving already-served
    # versions untouched. 16 hex chars (64 bits) is collision-safe across the
    # handful of key-set versions this project will ever have.
    canonical = json.dumps(
        {name: entry["sha256"] for name, entry in keys.items()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    version = hashlib.sha256(canonical).hexdigest()[:16]
    prefix = f"{args.prefix.rstrip('/')}/{version}"

    manifest = {"prefix": prefix, "keys": keys}
    with open(out, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {out} ({len(keys)} keys, prefix={prefix})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
