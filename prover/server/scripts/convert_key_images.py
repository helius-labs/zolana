#!/usr/bin/env python3
"""Reproduce the memory-image migration from authenticated published keys.

Build cmd/convert-key-image first. This script never publishes artifacts or
modifies a lockfile. Pass --expected-lock to verify the resulting key set.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request

SERVER = Path(__file__).resolve().parent.parent


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def matches(path, entry):
    return path.is_file() and path.stat().st_size == entry["size"] and digest(path) == entry["sha256"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("keys_dir", type=Path)
    parser.add_argument("names", nargs="*")
    parser.add_argument("--converter", type=Path, required=True)
    parser.add_argument("--expected-lock", type=Path)
    parser.add_argument("--discard-source", action="store_true", help="remove each compressed source after successful conversion")
    args = parser.parse_args()
    source = json.loads((SERVER / "scripts/key-image-source.lock").read_text())
    expected = json.loads(args.expected_lock.read_text())["keys"] if args.expected_lock else None
    args.keys_dir.mkdir(parents=True, exist_ok=True)
    cache = args.keys_dir / "compressed-source"
    cache.mkdir(exist_ok=True)
    for name in args.names or sorted(source["keys"]):
        entry = source["keys"][name]
        target = args.keys_dir / name
        if expected and matches(target, expected[name]):
            continue
        original = cache / name
        if not matches(original, entry):
            if entry.get("source") == "release":
                base = "https://github.com/helius-labs/zolana/releases/download/custom-ring-keys-v14"
            else:
                base = "https://d3gbdb0egjwcw9.cloudfront.net/" + source["prefix"]
            print("download", name, flush=True)
            fd, temporary = tempfile.mkstemp(dir=cache)
            os.close(fd)
            try:
                urllib.request.urlretrieve(base + "/" + name, temporary)
                if not matches(Path(temporary), entry):
                    raise RuntimeError("source checksum mismatch: " + name)
                os.replace(temporary, original)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        header = 0 if name.startswith("custom_ring_") else 8 if name.startswith("batch_") else 12
        print("convert", name, flush=True)
        subprocess.run([str(args.converter.resolve()), "--input", str(original), "--output", str(target),
                        "--sha256", entry["sha256"], "--header-bytes", str(header)], check=True)
        if expected and not matches(target, expected[name]):
            raise RuntimeError("converted checksum mismatch: " + name)
        print(name, target.stat().st_size, digest(target), flush=True)
        if args.discard_source:
            original.unlink()


if __name__ == "__main__":
    main()
