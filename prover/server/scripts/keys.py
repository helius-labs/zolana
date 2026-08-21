#!/usr/bin/env python3
"""Generate, publish, and verify the public proving keys.

Rotation is intentionally a laptop-operated release step. A failed run can
leave an unreferenced version folder in S3, but it does not modify the
repository until every object in the proposed manifest is publicly reachable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_DIR = SCRIPT_DIR.parent
REPO_ROOT = SERVER_DIR.parent.parent
LOCKFILE = SERVER_DIR / "prover/provingkeys/proving-keys.lock"
FINGERPRINT_FILE = SERVER_DIR / "prover/fingerprint/fingerprint_test.go"
INTERFACE_VKEY_DIR = REPO_ROOT / "program-libs/interface/src/verifying_keys"
BATCH_VKEY_DIR = (
    REPO_ROOT / "program-libs/batched-merkle-tree/src/verify/verifying_keys"
)

DEFAULT_BASE_URL = "https://d3gbdb0egjwcw9.cloudfront.net"
DEFAULT_BUCKET = "zolana-proving-keys"
BASE_PREFIX = "proving-keys"
CHUNK_SIZE = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TRANSFER_KEY_RE = re.compile(
    r"^(transfer_confidential|transfer_ring|transfer_p256_ring|"
    r"transfer_ring_authority)_(\d+)_(\d+)\.key$"
)
BATCH_KEY_RE = re.compile(r"^batch_address-append_(\d+)_(\d+)\.key$")
SET_NAMES = (
    "all", "batch", "merge", "transfer", "transfer-confidential",
    "transfer-p256-ring", "transfer-ring", "transfer-ring-authority",
)


@dataclass(frozen=True)
class KeySpec:
    name: str
    sets: frozenset[str]
    setup_args: tuple[str, ...]
    vkey_dir: Path

    @property
    def module(self) -> str:
        return self.name.removesuffix(".key").replace("-", "_")


def spec_for_name(name: str) -> KeySpec:
    transfer = TRANSFER_KEY_RE.fullmatch(name)
    if transfer:
        prefix, n_inputs, n_outputs = transfer.groups()
        circuit = prefix.replace("_", "-")
        return KeySpec(
            name=name,
            sets=frozenset(("all", "transfer", circuit)),
            setup_args=(
                "setup-transfer", "--circuit", circuit,
                "--n-inputs", n_inputs, "--n-outputs", n_outputs,
            ),
            vkey_dir=INTERFACE_VKEY_DIR,
        )

    if name in ("merge_8_1.key", "merge_ring_8_1.key"):
        circuit = "merge-ring" if name.startswith("merge_ring") else "merge"
        return KeySpec(
            name=name,
            sets=frozenset(("all", "merge")),
            setup_args=("setup-merge", "--circuit", circuit),
            vkey_dir=INTERFACE_VKEY_DIR,
        )

    batch = BATCH_KEY_RE.fullmatch(name)
    if batch:
        height, batch_size = batch.groups()
        return KeySpec(
            name=name,
            sets=frozenset(("all", "batch")),
            setup_args=(
                "setup", "--circuit", "address-append",
                "--address-append-tree-height", height,
                "--address-append-batch-size", batch_size,
            ),
            vkey_dir=BATCH_VKEY_DIR,
        )
    raise RotationError(f"unsupported key name in manifest: {name}")


class RotationError(RuntimeError):
    pass


def run(command: list[str], *, cwd: Path = REPO_ROOT,
        env: dict[str, str] | None = None, capture: bool = False) -> subprocess.CompletedProcess[str]:
    print(f"+ {shlex.join(command)}", file=sys.stderr, flush=True)
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def load_manifest() -> dict:
    try:
        manifest = json.loads(LOCKFILE.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RotationError(f"cannot read {LOCKFILE}: {error}") from error

    keys = manifest.get("keys")
    if not isinstance(keys, dict):
        raise RotationError(f"{LOCKFILE} has no keys map")
    for name, entry in keys.items():
        spec_for_name(name)
        if not isinstance(entry, dict):
            raise RotationError(f"invalid lock entry for {name}")
        digest = entry.get("sha256")
        size = entry.get("size")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise RotationError(f"invalid sha256 for {name}: {digest!r}")
        if not isinstance(size, int) or size <= 0:
            raise RotationError(f"invalid size for {name}: {size!r}")
    prefix = manifest.get("prefix")
    if not isinstance(prefix, str) or not prefix.strip("/"):
        raise RotationError(f"invalid prefix: {prefix!r}")
    return manifest


def object_path(manifest: dict, name: str) -> str:
    return f"{manifest['prefix'].strip('/')}/{name}"


def object_url(manifest: dict, name: str) -> str:
    base = os.environ.get("ZOLANA_PROVING_KEYS_URL", DEFAULT_BASE_URL).rstrip("/")
    return f"{base}/{urllib.parse.quote(object_path(manifest, name), safe='/')}"


def verify_object(manifest: dict, name: str, *, full: bool) -> None:
    entry = manifest["keys"][name]
    request = urllib.request.Request(
        object_url(manifest, name), method="GET" if full else "HEAD"
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status != 200:
            raise RotationError(f"{name}: HTTP {response.status}")
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) != entry["size"]:
            raise RotationError(
                f"{name}: remote size {content_length}, expected {entry['size']}"
            )
        if not full:
            if content_length is None:
                raise RotationError(f"{name}: response has no Content-Length")
            return

        digest = hashlib.sha256()
        size = 0
        for block in iter(lambda: response.read(CHUNK_SIZE), b""):
            digest.update(block)
            size += len(block)
        if size != entry["size"] or digest.hexdigest() != entry["sha256"]:
            raise RotationError(
                f"{name}: downloaded bytes do not match the lockfile"
            )


def verify_manifest(manifest: dict, *, full: bool, retries: int = 1) -> None:
    failures: list[str] = []
    for attempt in range(retries):
        failures.clear()
        for name in sorted(manifest["keys"]):
            try:
                verify_object(manifest, name, full=full)
            except (OSError, ValueError, RotationError) as error:
                failures.append(f"{name}: {error}")
        if not failures:
            print(f"verified {len(manifest['keys'])} published keys")
            return
        if attempt + 1 < retries:
            print(
                f"waiting for {len(failures)} object(s) to become reachable...",
                file=sys.stderr,
            )
            time.sleep(2)
    raise RotationError("published-key verification failed:\n  " + "\n  ".join(failures))


FINGERPRINT_LINE = re.compile(
    r'^(?P<start>\s*"(?P<name>[^"]+)":\s*\{constraints:\s*)'
    r'(?P<constraints>\d+)(?P<middle>,\s*public:\s*)'
    r'(?P<public>\d+)(?P<end>\},\s*)$',
    re.MULTILINE,
)


def compile_fingerprints(selected_names: set[str], specs: list[KeySpec]) -> str:
    source = FINGERPRINT_FILE.read_text()
    expected = {
        match.group("name"): (
            int(match.group("constraints")), int(match.group("public"))
        )
        for match in FINGERPRINT_LINE.finditer(source)
    }
    env = os.environ.copy()
    env["UPDATE_FINGERPRINTS"] = "1"
    result = run(
        [
            "go", "test", "./prover/fingerprint/",
            "-run", "^TestCircuitFingerprintsMatchRotatedKeys$", "-v",
        ],
        cwd=SERVER_DIR,
        env=env,
        capture=True,
    )
    assert result.stdout is not None
    print(result.stdout, file=sys.stderr, end="")
    actual = {
        match.group("name"): (
            int(match.group("constraints")), int(match.group("public"))
        )
        for match in FINGERPRINT_LINE.finditer(result.stdout)
    }
    names_in_set = lambda set_name: {
        spec.name for spec in specs if set_name in spec.sets
    }
    families = {
        "transfer_confidential_2_3": names_in_set("transfer-confidential"),
        "transfer_ring_2_3": names_in_set("transfer-ring"),
        "transfer_ring_authority_2_2": names_in_set("transfer-ring-authority"),
        "transfer_p256_ring_2_3": names_in_set("transfer-p256-ring"),
        "merge_8_1": {"merge_8_1.key"},
        "merge_ring_8_1": {"merge_ring_8_1.key"},
        "batch_address-append_40_10": names_in_set("batch"),
    }
    if set(actual) != set(families) or set(expected) != set(actual):
        raise RotationError(
            "could not identify the complete fingerprint set in Go test output/source"
        )

    for name, value in actual.items():
        if value != expected[name]:
            required = families[name]
            omitted = sorted(required - selected_names)
            if omitted:
                raise RotationError(
                    f"circuit fingerprint {name} changed, but this rotation omits "
                    f"{len(omitted)} affected key(s); rotate its complete set"
                )

    def replace(match: re.Match[str]) -> str:
        constraints, public = actual[match.group("name")]
        return (
            f"{match.group('start')}{constraints}"
            f"{match.group('middle')}{public}{match.group('end')}"
        )

    return FINGERPRINT_LINE.sub(replace, source)


def generate(selected: list[KeySpec], staging: Path) -> dict[str, Path]:
    binary = staging / "light-prover"
    keys_dir = staging / "keys"
    raw_vkeys = staging / "raw-vkeys"
    generated_vkeys = staging / "rust-vkeys"
    keys_dir.mkdir()
    raw_vkeys.mkdir()
    generated_vkeys.mkdir()

    run(["go", "build", "-o", str(binary), "."], cwd=SERVER_DIR)
    run(["cargo", "build", "-q", "-p", "xtask"], cwd=REPO_ROOT)
    xtask = REPO_ROOT / "target/debug/xtask"
    if not xtask.is_file():
        raise RotationError(f"cargo did not produce {xtask}")

    outputs: dict[str, Path] = {}
    for spec in selected:
        key_path = keys_dir / spec.name
        command = [str(binary), *spec.setup_args, "--output", str(key_path)]
        if spec.name.startswith("batch_address-append"):
            command.extend(("--output-vkey", str(staging / f"{spec.module}.vkey")))
        run(command, cwd=SERVER_DIR)
        if not key_path.is_file() or key_path.stat().st_size == 0:
            raise RotationError(f"setup did not produce {key_path}")

        raw_vkey = raw_vkeys / f"{spec.module}.vkbin"
        run([
            str(binary), "export-vk", "--keys-file", str(key_path),
            "--output", str(raw_vkey),
        ], cwd=SERVER_DIR)
        output_dir = generated_vkeys / spec.module
        output_dir.mkdir()
        run([
            str(xtask), "bsb22-vk", str(raw_vkey), str(output_dir),
            f"{spec.module}.rs",
        ])
        generated = output_dir / f"{spec.module}.rs"
        if not generated.is_file():
            raise RotationError(f"vk codegen did not produce {generated}")
        run(["rustfmt", str(generated)])
        outputs[spec.name] = key_path
    return outputs


def proposed_manifest(current: dict, generated: dict[str, Path]) -> dict:
    entries = {name: dict(entry) for name, entry in current["keys"].items()}
    for name, path in generated.items():
        entries[name] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    entries = dict(sorted(entries.items()))
    canonical = json.dumps(
        {name: entry["sha256"] for name, entry in entries.items()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    version = hashlib.sha256(canonical).hexdigest()[:16]
    return {"prefix": f"{BASE_PREFIX}/{version}", "keys": entries}


def check_aws_access() -> None:
    if shutil.which("aws") is None:
        raise RotationError("aws CLI is required for rotation")
    try:
        result = run(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            capture=True,
        )
    except subprocess.CalledProcessError as error:
        profile = os.environ.get("AWS_PROFILE") or os.environ.get("AWS_DEFAULT_PROFILE")
        login = "aws sso login"
        if profile:
            login += f" --profile {shlex.quote(profile)}"
        detail = (error.stdout or "AWS CLI did not return an error message").strip()
        raise RotationError(
            f"AWS credentials are not usable:\n{detail}\nRefresh them with: {login}"
        ) from error
    try:
        identity = json.loads(result.stdout or "")
        print(f"AWS caller: {identity['Arn']}", file=sys.stderr)
    except (json.JSONDecodeError, KeyError) as error:
        raise RotationError("aws returned an invalid caller identity") from error


def publish(current: dict, proposed: dict, generated: dict[str, Path]) -> None:
    bucket = os.environ.get("ZOLANA_PROVING_KEYS_BUCKET", DEFAULT_BUCKET)

    old_prefix = current["prefix"].strip("/")
    new_prefix = proposed["prefix"].strip("/")
    if old_prefix == new_prefix:
        raise RotationError("generated keys did not change the manifest version")

    # Unchanged multi-gigabyte objects are copied inside S3, not downloaded and
    # re-uploaded through the developer's laptop.
    for name in sorted(set(proposed["keys"]) - set(generated)):
        run([
            "aws", "s3", "cp",
            f"s3://{bucket}/{old_prefix}/{name}",
            f"s3://{bucket}/{new_prefix}/{name}",
            "--only-show-errors",
        ])

    for name, path in sorted(generated.items()):
        run([
            "aws", "s3", "cp", str(path),
            f"s3://{bucket}/{new_prefix}/{name}",
            "--only-show-errors",
        ])

    # This is the publication boundary. No repository file has changed yet.
    verify_manifest(proposed, full=False, retries=30)


def atomic_write(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.keys-tmp")
    temporary.write_bytes(content)
    os.replace(temporary, path)


def commit_generated(
    selected: list[KeySpec], generated: dict[str, Path],
    manifest: dict, fingerprints: str,
) -> None:
    for spec in selected:
        generated_vk = (
            generated[spec.name].parents[1]
            / "rust-vkeys" / spec.module / f"{spec.module}.rs"
        )
        atomic_write(spec.vkey_dir / f"{spec.module}.rs", generated_vk.read_bytes())
    atomic_write(FINGERPRINT_FILE, fingerprints.encode())
    # Write the lock last: it is the only pointer to the newly published objects.
    lock = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    atomic_write(LOCKFILE, lock)


def select(args: argparse.Namespace, specs: list[KeySpec]) -> list[KeySpec]:
    if args.key:
        name = args.key if args.key.endswith(".key") else f"{args.key}.key"
        spec = next((spec for spec in specs if spec.name == name), None)
        if spec is None:
            raise RotationError(f"unknown proving key {args.key!r}")
        return [spec]
    return [spec for spec in specs if args.set_name in spec.sets]


def rotate(args: argparse.Namespace) -> None:
    current = load_manifest()
    specs = [spec_for_name(name) for name in sorted(current["keys"])]
    selected = select(args, specs)
    selected_names = {spec.name for spec in selected}
    print(f"rotating {len(selected)} of {len(specs)} proving keys", file=sys.stderr)

    check_aws_access()
    fingerprints = compile_fingerprints(selected_names, specs)
    with tempfile.TemporaryDirectory(prefix="zolana-proving-keys-") as directory:
        staging = Path(directory)
        generated = generate(selected, staging)
        manifest = proposed_manifest(current, generated)
        publish(current, manifest, generated)
        commit_generated(selected, generated, manifest, fingerprints)

    print("rotation complete; review and commit the lock, vkeys, and fingerprints")


def verify(args: argparse.Namespace) -> None:
    manifest = load_manifest()
    verify_manifest(manifest, full=args.full)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    rotate_parser = commands.add_parser(
        "rotate", help="generate, publish, then update repository pins"
    )
    selection = rotate_parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--set", dest="set_name", choices=SET_NAMES)
    selection.add_argument("--key", help="one exact key name, with or without .key")
    rotate_parser.set_defaults(handler=rotate)

    verify_parser = commands.add_parser(
        "verify", help="check that every locked object is publicly reachable"
    )
    verify_parser.add_argument(
        "--full", action="store_true",
        help="download and hash all keys (default: HEAD and size only)",
    )
    verify_parser.set_defaults(handler=verify)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (RotationError, subprocess.CalledProcessError, urllib.error.URLError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
