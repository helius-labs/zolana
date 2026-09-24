#!/usr/bin/env python3
"""Generate, publish, and verify the Zolana proving keys.

The committed lockfile prover/server/prover/provingkeys/proving-keys.lock is
the proving-key version. It pins every key's sha256 and size, and its prefix
`proving-keys/<version-hash>` names the immutable object-store folder the
prover downloads from. This tool is the only writer of that file.

  check      offline: lockfile schema and prefix, key table, VK modules, fingerprints
  verify     read-only: every pinned key is served with its pinned size (--full: sha256)
  rotate     regenerate keys, VKs, fingerprints and the lock, then publish
             (--no-publish stages and updates the repository only)
  publish    upload a staged rotation to its new folder, verify it, update the repository
  vkeys      regenerate (or --check) the committed Rust VKs from local proving keys
  migrate-release-keys
             stage moving the `source: release` keys into the object store

A rotation stages everything in one directory (keys, generated repository
files, rotation.json) before anything leaves the machine. Publishing copies
unchanged keys inside S3, uploads only regenerated or missing keys, and
touches the repository only after every object in the new folder is publicly
reachable. A failed publish keeps the directory; rerun `publish DIR`.
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
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]

LOCK_REL = Path("prover/server/prover/provingkeys/proving-keys.lock")
FINGERPRINT_REL = Path("prover/server/prover/fingerprint/fingerprint_test.go")
DOWNLOADER_REL = Path("prover/server/prover/common/key_downloader.go")
SERVER_REL = Path("prover/server")
INTERFACE_VK_REL = Path("program-libs/interface/src/verifying_keys")
TREE_VK_REL = Path("program-libs/tree/src/nullifier_tree/verify/verifying_keys")
RING_VK_REL = Path("custom-rings/interface/src")
RING_KEYS_SH_REL = Path("prover/server/scripts/ring_keys.sh")
JUSTFILE_REL = Path("justfile")
KEYS_DIR_REL = Path("prover/server/proving-keys")
ROTATIONS_REL = Path("target/proving-keys-rotation")

BASE_PREFIX = "proving-keys"
PLAN_FILE = "rotation.json"
RELEASE_SOURCE = "release"
# Transitional: the custom-ring keys are pinned with `source: release` and
# served from this GitHub release, never from the object store. The same URL is
# the default in `just ensure-custom-ring-live-keys`; `check` keeps them equal.
DEFAULT_RELEASE_URL = (
    "https://github.com/helius-labs/zolana/releases/download/custom-ring-keys-v14"
)
DEFAULT_BUCKET = "zolana-proving-keys"
CHUNK = 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class KeysError(RuntimeError):
    pass


# --- key table --------------------------------------------------------------

TRANSFER_RE = re.compile(r"(transfer_[a-z0-9_]*[a-z])_(\d+)_(\d+)")
MERGE_RE = re.compile(r"(merge(?:_[a-z]+)*)_(\d+)_(\d+)")
BATCH_RE = re.compile(r"batch_address-append_(\d+)_(\d+)")
RING_RE = re.compile(r"custom_ring_([a-z](?:[a-z_]*[a-z])?)")


@dataclass(frozen=True)
class KeySpec:
    """Everything derivable from a key filename: its circuit, how to set it
    up, and where its committed Rust verifying key lives."""

    name: str
    group: str
    circuit: str
    setup: tuple[str, ...]
    vk_path: Path
    module_dir: Path | None

    @property
    def stem(self) -> str:
        return self.name.removesuffix(".key")

    @property
    def module(self) -> str:
        return self.vk_path.stem

    @property
    def sets(self) -> frozenset[str]:
        return frozenset(("all", self.group, self.circuit.replace("_", "-")))

    @property
    def writes_vkey(self) -> bool:
        # The nullifier-tree `setup` command insists on a separate vkey output.
        return self.setup[0] == "setup"


def key_name(value: str) -> str:
    return value if value.endswith(".key") else f"{value}.key"


def spec_for_name(name: str) -> KeySpec:
    if not name.endswith(".key"):
        raise KeysError(f"{name}: proving keys are named <stem>.key")
    stem = name.removesuffix(".key")

    if match := TRANSFER_RE.fullmatch(stem):
        circuit, n_in, n_out = match.groups()
        return KeySpec(
            name, "transfer", circuit,
            ("setup-transfer", "--circuit", circuit.replace("_", "-"),
             "--n-inputs", n_in, "--n-outputs", n_out),
            INTERFACE_VK_REL / f"{stem}.rs", INTERFACE_VK_REL,
        )
    if match := MERGE_RE.fullmatch(stem):
        circuit, n_in, n_out = match.groups()
        if n_out != "1":
            raise KeysError(f"{name}: merge circuits have exactly one output")
        return KeySpec(
            name, "merge", circuit,
            ("setup-merge", "--circuit", circuit.replace("_", "-"), "--n-inputs", n_in),
            INTERFACE_VK_REL / f"{stem}.rs", INTERFACE_VK_REL,
        )
    if match := BATCH_RE.fullmatch(stem):
        height, batch_size = match.groups()
        return KeySpec(
            name, "batch", "batch_address-append",
            ("setup", "--circuit", "address-append",
             "--address-append-tree-height", height,
             "--address-append-batch-size", batch_size),
            TREE_VK_REL / f"{stem.replace('-', '_')}.rs", TREE_VK_REL,
        )
    if match := RING_RE.fullmatch(stem):
        (ring,) = match.groups()
        return KeySpec(
            name, "custom-ring", stem,
            (f"setup-custom-ring-{ring.replace('_', '-')}",),
            RING_VK_REL / f"{ring}_verifying_key.rs", None,
        )
    raise KeysError(f"{name}: no known circuit family for this key name")


def key_table(names) -> dict[str, KeySpec]:
    return {name: spec_for_name(name) for name in sorted(names)}


def known_sets(specs: dict[str, KeySpec]) -> set[str]:
    return set().union(*(spec.sets for spec in specs.values()))


def select_keys(
    lock_names, sets=(), keys=(), skips=(), allow_add=False,
) -> list[str]:
    specs = key_table(lock_names)
    available = known_sets(specs)
    chosen: set[str] = set()
    for set_name in sets:
        if set_name not in available:
            raise KeysError(
                f"unknown set {set_name!r}; known: {', '.join(sorted(available))}"
            )
        chosen |= {name for name, spec in specs.items() if set_name in spec.sets}
    for value in keys:
        name = key_name(value)
        if name not in specs:
            spec_for_name(name)
            if not allow_add:
                raise KeysError(
                    f"{name} is not in the lockfile; pass --add to introduce a new key"
                )
        chosen.add(name)
    for value in skips:
        name = key_name(value)
        if name not in chosen:
            raise KeysError(f"--skip {name}: not part of the selection")
        chosen.discard(name)
    if not chosen:
        raise KeysError("the selection is empty")
    return sorted(chosen)


# --- lockfile ---------------------------------------------------------------


def compute_prefix(keys: dict) -> str:
    # The version hash covers each object-store key's name and sha256. Entries
    # with a `source` are served from elsewhere and do not move the folder.
    # With no `source` entries left this is simply a hash over every key.
    canonical = json.dumps(
        {name: entry["sha256"] for name, entry in keys.items() if "source" not in entry},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return f"{BASE_PREFIX}/{hashlib.sha256(canonical).hexdigest()[:16]}"


def render_lock(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def lock_errors(manifest) -> list[str]:
    if not isinstance(manifest, dict) or set(manifest) != {"keys", "prefix"}:
        return ["lockfile must be an object with exactly `keys` and `prefix`"]
    keys = manifest["keys"]
    if not isinstance(keys, dict) or not keys:
        return ["lockfile `keys` must be a non-empty object"]
    errors = []
    for name, entry in sorted(keys.items()):
        try:
            spec_for_name(name)
        except KeysError as error:
            errors.append(str(error))
        if not isinstance(entry, dict):
            errors.append(f"{name}: entry must be an object")
            continue
        extra = set(entry) - {"sha256", "size", "source"}
        if extra:
            errors.append(f"{name}: unknown fields {sorted(extra)}")
        if not isinstance(entry.get("sha256"), str) or not SHA256_RE.fullmatch(entry["sha256"]):
            errors.append(f"{name}: sha256 must be 64 lowercase hex characters")
        size = entry.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            errors.append(f"{name}: size must be a positive integer")
        if "source" in entry and entry["source"] != RELEASE_SOURCE:
            errors.append(f"{name}: unknown source {entry['source']!r}")
    if not isinstance(manifest["prefix"], str):
        errors.append("prefix must be a string")
    elif not errors and manifest["prefix"] != compute_prefix(keys):
        errors.append(
            f"prefix {manifest['prefix']} does not match the key set, "
            f"expected {compute_prefix(keys)}"
        )
    return errors


def propose_manifest(base: dict, generated: dict[str, tuple[str, int]]) -> dict:
    keys = {name: dict(entry) for name, entry in base["keys"].items()}
    for name, (digest, size) in generated.items():
        entry = {"sha256": digest, "size": size}
        # A regenerated key keeps being served from where it was served.
        if "source" in keys.get(name, {}):
            entry["source"] = keys[name]["source"]
        keys[name] = entry
    return {"keys": keys, "prefix": compute_prefix(keys)}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


# --- fingerprints -----------------------------------------------------------

FINGERPRINT_RE = re.compile(
    r'^(?P<head>\s*"(?P<name>[^"]+)":\s*\{constraints:\s*)(?P<constraints>\d+)'
    r"(?P<mid>,\s*public:\s*)(?P<public>\d+)(?P<tail>\},?)[ \t]*$",
    re.MULTILINE,
)


def parse_fingerprints(text: str) -> dict[str, tuple[int, int]]:
    return {
        m["name"]: (int(m["constraints"]), int(m["public"]))
        for m in FINGERPRINT_RE.finditer(text)
    }


def fingerprint_families(fingerprints, key_names) -> dict[str, frozenset[str]]:
    """Map each fingerprinted circuit to every key built from that circuit.

    A fingerprint is compiled for one representative shape, so a change means
    every shape of the circuit has to be rotated."""
    specs = key_table(key_names)
    by_circuit: dict[str, set[str]] = {}
    for name, spec in specs.items():
        by_circuit.setdefault(spec.circuit, set()).add(name)
    families, errors = {}, []
    for fp in sorted(fingerprints):
        try:
            circuit = spec_for_name(key_name(fp)).circuit
        except KeysError as error:
            errors.append(f"fingerprint {fp}: {error}")
            continue
        if circuit not in by_circuit:
            errors.append(f"fingerprint {fp} matches no pinned key")
            continue
        families[fp] = frozenset(by_circuit[circuit])
    covered = set().union(*families.values()) if families else set()
    for name in sorted(set(specs) - covered):
        errors.append(f"{name} has no circuit fingerprint")
    if errors:
        raise KeysError("\n".join(errors))
    return families


def update_fingerprints(source: str, actual, selected, families) -> str:
    expected = parse_fingerprints(source)
    if set(expected) != set(actual):
        raise KeysError(
            "the compiled fingerprint set differs from the pinned one: "
            f"pinned {sorted(expected)}, compiled {sorted(actual)}"
        )
    for name in sorted(actual):
        if actual[name] != expected[name]:
            omitted = sorted(families[name] - set(selected))
            if omitted:
                raise KeysError(
                    f"circuit {name} changed ({expected[name]} -> {actual[name]}) "
                    f"but this rotation omits {', '.join(omitted)}"
                )

    def replace(m: re.Match) -> str:
        constraints, public = actual[m["name"]]
        return f"{m['head']}{constraints}{m['mid']}{public}{m['tail']}"

    return FINGERPRINT_RE.sub(replace, source)


# --- mod.rs module lists ----------------------------------------------------

MODULE_RE = re.compile(r"pub mod (\w+);")


def split_module_list(text: str) -> tuple[str, str, list[str]]:
    lines = text.splitlines(keepends=True)
    first = next((i for i, line in enumerate(lines) if MODULE_RE.fullmatch(line.strip())), None)
    if first is None:
        raise KeysError("mod.rs declares no `pub mod`")
    start, attr = first, ""
    if first > 0 and lines[first - 1].startswith("#["):
        start, attr = first - 1, lines[first - 1]
    modules = []
    for line in lines[start:]:
        if line == attr:
            continue
        match = MODULE_RE.fullmatch(line.strip())
        if not match:
            raise KeysError(f"mod.rs: unexpected line after the module list: {line.strip()!r}")
        modules.append(match[1])
    return "".join(lines[:start]), attr, modules


def render_module_list(text: str, modules) -> str:
    preamble, attr, _ = split_module_list(text)
    return preamble + "".join(f"{attr}pub mod {module};\n" for module in sorted(modules))


def modules_by_dir(specs: dict[str, KeySpec]) -> dict[Path, list[str]]:
    dirs: dict[Path, list[str]] = {}
    for spec in specs.values():
        if spec.module_dir is not None:
            dirs.setdefault(spec.module_dir, []).append(spec.module)
    return {d: sorted(m) for d, m in dirs.items()}


# --- repository -------------------------------------------------------------


@dataclass(frozen=True)
class Repo:
    root: Path

    def path(self, rel: Path | str) -> Path:
        return self.root / rel

    def load_lock(self) -> dict:
        try:
            return json.loads(self.path(LOCK_REL).read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise KeysError(f"cannot read {LOCK_REL}: {error}") from error

    def base_url(self) -> str:
        if value := os.environ.get("ZOLANA_PROVING_KEYS_URL", "").strip():
            return value.rstrip("/")
        source = self.path(DOWNLOADER_REL).read_text()
        match = re.search(r'defaultProvingKeysBaseURL\s*=\s*"([^"]+)"', source)
        if not match:
            raise KeysError(f"no defaultProvingKeysBaseURL in {DOWNLOADER_REL}")
        return match[1].rstrip("/")

    def default_keys_dir(self) -> Path:
        value = os.environ.get("ZOLANA_SPP_KEYS_DIR")
        return self.root / value if value else self.path(KEYS_DIR_REL)


def release_url() -> str:
    return os.environ.get("ZOLANA_RING_KEYS_URL", DEFAULT_RELEASE_URL).rstrip("/")


def key_url(repo: Repo, manifest: dict, name: str) -> str:
    source = manifest["keys"][name].get("source")
    if source is None:
        return f"{repo.base_url()}/{manifest['prefix'].strip('/')}/{name}"
    if source == RELEASE_SOURCE:
        return f"{release_url()}/{name}"
    raise KeysError(f"{name}: unknown source {source!r}")


def ring_keys_sh_names(text: str) -> set[str]:
    body = re.search(r"ring_keys=\((.*?)\)", text, re.DOTALL)
    return set(body[1].split()) if body else set()


def check_repo(repo: Repo) -> list[str]:
    text = repo.path(LOCK_REL).read_text()
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as error:
        return [f"{LOCK_REL}: {error}"]
    errors = lock_errors(manifest)
    if errors:
        return errors
    if text != render_lock(manifest):
        errors.append(f"{LOCK_REL} is not in canonical form (indent 2, sorted keys)")

    specs = key_table(manifest["keys"])
    fingerprints = parse_fingerprints(repo.path(FINGERPRINT_REL).read_text())
    try:
        fingerprint_families(fingerprints, specs)
    except KeysError as error:
        errors.extend(str(error).splitlines())

    for spec in specs.values():
        if not repo.path(spec.vk_path).is_file():
            errors.append(f"{spec.name}: missing verifying key {spec.vk_path}")
    for module_dir, modules in modules_by_dir(specs).items():
        _, _, listed = split_module_list(repo.path(module_dir / "mod.rs").read_text())
        if listed != modules:
            errors.append(
                f"{module_dir}/mod.rs lists {sorted(set(listed) ^ set(modules))} "
                "differently from the lockfile"
            )

    released = {n for n, e in manifest["keys"].items() if e.get("source") == RELEASE_SOURCE}
    listed = ring_keys_sh_names(repo.path(RING_KEYS_SH_REL).read_text())
    if listed != released:
        errors.append(f"{RING_KEYS_SH_REL} does not list the `source: release` keys")
    if released and DEFAULT_RELEASE_URL not in repo.path(JUSTFILE_REL).read_text():
        errors.append(f"justfile does not fetch the release keys from {DEFAULT_RELEASE_URL}")
    try:
        repo.base_url()
    except KeysError as error:
        errors.append(str(error))
    return errors


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.keys-tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def install_key(source: Path, target: Path) -> None:
    """Link a key into the live keys dir. The prover replaces a mismatched key
    by renaming a fresh download over it, which leaves the staged inode (and so
    the rotation directory) intact."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.samefile(source):
        return
    temporary = target.with_name(f".{target.name}.keys-tmp")
    temporary.unlink(missing_ok=True)
    try:
        os.link(source, temporary)
    except OSError:
        shutil.copyfile(source, temporary)
    os.replace(temporary, target)


# --- rotation directory -----------------------------------------------------


@dataclass
class Rotation:
    directory: Path
    base: dict
    manifest: dict
    generated: list[str]
    staged: list[str] = field(default_factory=list)

    @property
    def keys_dir(self) -> Path:
        return self.directory / "keys"

    @property
    def repo_dir(self) -> Path:
        return self.directory / "repo"

    def stage(self, rel: Path, data: bytes) -> None:
        atomic_write(self.repo_dir / rel, data)
        if str(rel) not in self.staged:
            self.staged.append(str(rel))

    def save(self) -> None:
        body = {
            "base": self.base,
            "manifest": self.manifest,
            "generated": sorted(self.generated),
            "staged": self.staged,
        }
        atomic_write(self.directory / PLAN_FILE, (json.dumps(body, indent=2) + "\n").encode())

    @classmethod
    def load(cls, directory: Path) -> "Rotation":
        try:
            body = json.loads((directory / PLAN_FILE).read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise KeysError(f"{directory} holds no readable {PLAN_FILE}: {error}") from error
        return cls(directory, body["base"], body["manifest"], body["generated"], body["staged"])


def apply_rotation(repo: Repo, rotation: Rotation, keys_dir: Path | None) -> None:
    current = repo.path(LOCK_REL).read_text()
    if current == render_lock(rotation.manifest):
        print(f"repository already pins {rotation.manifest['prefix']}", file=sys.stderr)
    elif current != render_lock(rotation.base):
        raise KeysError(
            f"{LOCK_REL} changed since this rotation was planned; "
            "re-run the rotation on top of the current lockfile"
        )
    else:
        # The lockfile goes last: it is the only pointer to the new keys.
        for rel in sorted(rotation.staged, key=lambda rel: rel == str(LOCK_REL)):
            atomic_write(repo.path(rel), (rotation.repo_dir / rel).read_bytes())
            print(f"updated {rel}", file=sys.stderr)
    if keys_dir is not None:
        for name in rotation.generated:
            install_key(rotation.keys_dir / name, keys_dir / name)


# --- object store and public reads -------------------------------------------


def run(command, *, cwd: Path | None = None, env=None, capture=False) -> str:
    print(f"+ {shlex.join(str(part) for part in command)}", file=sys.stderr, flush=True)
    result = subprocess.run(
        [str(part) for part in command], cwd=cwd, env=env, check=False, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if result.returncode != 0:
        detail = f"\n{result.stdout.strip()}" if capture and result.stdout else ""
        raise KeysError(f"`{shlex.join(str(p) for p in command)}` failed ({result.returncode}){detail}")
    return result.stdout or ""


class AwsStore:
    """The only code path that writes to the bucket."""

    def __init__(self, bucket: str):
        self.bucket = bucket

    def check_credentials(self) -> None:
        if shutil.which("aws") is None:
            raise KeysError("publishing needs the aws CLI")
        try:
            identity = json.loads(run(["aws", "sts", "get-caller-identity", "--output", "json"], capture=True))
        except (KeysError, json.JSONDecodeError) as error:
            profile = os.environ.get("AWS_PROFILE")
            login = "aws sso login" + (f" --profile {shlex.quote(profile)}" if profile else "")
            raise KeysError(f"AWS credentials are not usable ({error}); refresh with `{login}`") from error
        print(f"AWS caller: {identity.get('Arn')}", file=sys.stderr)

    def size(self, prefix: str, name: str) -> int | None:
        command = [
            "aws", "s3api", "head-object", "--bucket", self.bucket,
            "--key", f"{prefix}/{name}", "--query", "ContentLength", "--output", "text",
        ]
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if result.returncode == 0:
            return int(result.stdout.strip())
        if "(404)" in result.stderr or "Not Found" in result.stderr:
            return None
        raise KeysError(f"head-object {prefix}/{name}: {result.stderr.strip()}")

    def copy(self, source_prefix: str, prefix: str, name: str) -> None:
        run(["aws", "s3", "cp", f"s3://{self.bucket}/{source_prefix}/{name}",
             f"s3://{self.bucket}/{prefix}/{name}", "--only-show-errors"])

    def upload(self, path: Path, prefix: str, name: str) -> None:
        run(["aws", "s3", "cp", path, f"s3://{self.bucket}/{prefix}/{name}", "--only-show-errors"])


class _KeepHead(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and req.get_method() == "HEAD":
            new.method = "HEAD"
        return new


class PublicHttp:
    """Credential-free reads, the same view the prover's downloader has."""

    def __init__(self):
        self.opener = urllib.request.build_opener(_KeepHead())

    def _open(self, url: str, method: str):
        try:
            return self.opener.open(urllib.request.Request(url, method=method), timeout=120)
        except urllib.error.HTTPError as error:
            raise KeysError(f"HTTP {error.code}") from error
        except (urllib.error.URLError, OSError) as error:
            raise KeysError(str(error)) from error

    def size(self, url: str) -> int | None:
        """Content-Length, or None when the object does not exist (403/404)."""
        try:
            with self._open(url, "HEAD") as response:
                length = response.headers.get("Content-Length")
        except KeysError as error:
            if str(error) in ("HTTP 403", "HTTP 404"):
                return None
            raise
        if length is None:
            raise KeysError("response has no Content-Length")
        return int(length)

    def digest(self, url: str, sink: Path | None = None) -> tuple[int, str]:
        """Stream the object through sha256, optionally writing it to sink."""
        digest, size = hashlib.sha256(), 0
        with self._open(url, "GET") as response, (sink.open("wb") if sink else open(os.devnull, "wb")) as out:
            for block in iter(lambda: response.read(CHUNK), b""):
                digest.update(block)
                out.write(block)
                size += len(block)
        return size, digest.hexdigest()


class PublicStore:
    """Read-only stand-in for AwsStore, used by `publish --dry-run`."""

    def __init__(self, http: PublicHttp, base_url: str):
        self.http, self.base_url = http, base_url

    def size(self, prefix: str, name: str) -> int | None:
        return self.http.size(f"{self.base_url}/{prefix}/{name}")


# --- publishing -------------------------------------------------------------


@dataclass(frozen=True)
class Action:
    kind: str  # release | present | copy | upload
    name: str
    path: Path | None = None


def local_copy(name: str, entry: dict, dirs) -> Path | None:
    for directory in dirs:
        path = directory / name
        if path.is_file() and path.stat().st_size == entry["size"] and sha256_file(path) == entry["sha256"]:
            return path
    return None


def plan_publish(rotation: Rotation, store, local_dirs) -> list[Action]:
    """Decide, per key of the new manifest, how it reaches the new folder.

    Unchanged keys are copied inside S3 from the old folder; regenerated keys,
    and unchanged keys the old folder lacks, are uploaded from a verified local
    copy. Objects already in the new folder (an interrupted publish) are kept
    when their size matches and are never overwritten otherwise."""
    old = rotation.base["prefix"].strip("/")
    new = rotation.manifest["prefix"].strip("/")
    generated = set(rotation.generated)
    dirs = [rotation.keys_dir, *local_dirs]
    actions, problems = [], []
    for name, entry in sorted(rotation.manifest["keys"].items()):
        if "source" in entry:
            actions.append(Action("release", name))
            continue
        present = store.size(new, name)
        if present is not None:
            if present != entry["size"]:
                problems.append(
                    f"{name}: {new}/{name} already holds {present} bytes, the lock pins "
                    f"{entry['size']}; version folders are immutable, remove it by hand"
                )
            else:
                actions.append(Action("present", name))
            continue
        if name not in generated and old != new:
            if store.size(old, name) == entry["size"]:
                actions.append(Action("copy", name))
                continue
        path = local_copy(name, entry, dirs)
        if path is not None:
            actions.append(Action("upload", name, path))
            continue
        where = f"{old}/{name}" if old != new else f"{new}/{name}"
        problems.append(
            f"{name}: not in {where} with {entry['size']} bytes and no local copy "
            f"hashes to {entry['sha256']}; place a verified copy in {rotation.keys_dir}"
        )
    if problems:
        raise KeysError("cannot publish:\n  " + "\n  ".join(problems))
    return actions


# CloudFront may briefly serve a cached 403 for a path requested before upload.
VERIFY_ATTEMPTS = 30
VERIFY_DELAY_SECONDS = 10.0


def verify_published(repo: Repo, rotation: Rotation, actions, http) -> None:
    """Read back the new folder the way clients will. Bytes this machine
    produced or uploaded are downloaded and hashed; copies are checked by size."""
    generated = set(rotation.generated)
    pending = [a for a in actions if a.kind != "release"]
    for attempt in range(VERIFY_ATTEMPTS):
        failures = []
        for action in pending:
            entry = rotation.manifest["keys"][action.name]
            url = key_url(repo, rotation.manifest, action.name)
            try:
                if action.kind == "upload" or action.name in generated:
                    size, digest = http.digest(url)
                    if (size, digest) != (entry["size"], entry["sha256"]):
                        raise KeysError(f"served {size} bytes hashing to {digest}")
                elif (size := http.size(url)) != entry["size"]:
                    raise KeysError(f"served size {size}, expected {entry['size']}")
            except KeysError as error:
                failures.append(action)
                print(f"  {action.name}: {error}", file=sys.stderr)
        if not failures:
            print(f"verified {len(pending)} objects under {rotation.manifest['prefix']}", file=sys.stderr)
            return
        pending = failures
        if attempt + 1 < VERIFY_ATTEMPTS:
            print(f"waiting for {len(pending)} object(s)...", file=sys.stderr)
            time.sleep(VERIFY_DELAY_SECONDS)
    raise KeysError(f"{len(pending)} published object(s) failed verification")


def release_instructions(rotation: Rotation) -> str:
    released = [n for n in rotation.generated if rotation.manifest["keys"][n].get("source") == RELEASE_SOURCE]
    if not released:
        return ""
    files = " ".join(str(rotation.keys_dir / n) for n in sorted(released))
    return (
        "\nThe regenerated `source: release` keys are not in the object store. Publish them as\n"
        "a new GitHub release and point DEFAULT_RELEASE_URL (keys.py) and\n"
        "ensure-custom-ring-live-keys (justfile) at it:\n"
        f"  gh release create custom-ring-keys-vN --prerelease {files}\n"
    )


def publish(repo: Repo, rotation: Rotation, store, http, keys_dir: Path, *, dry_run=False) -> None:
    actions = plan_publish(rotation, store, [keys_dir])
    old = rotation.base["prefix"].strip("/")
    new = rotation.manifest["prefix"].strip("/")
    counts = {kind: sum(a.kind == kind for a in actions) for kind in ("present", "copy", "upload", "release")}
    print(
        f"{old} -> {new}: copy {counts['copy']}, upload {counts['upload']}, "
        f"already present {counts['present']}, release-hosted {counts['release']}",
        file=sys.stderr,
    )
    for action in actions:
        print(f"  {action.kind:8} {action.name}", file=sys.stderr)
    if dry_run:
        return
    for action in actions:
        if action.kind == "copy":
            store.copy(old, new, action.name)
        elif action.kind == "upload":
            store.upload(action.path, new, action.name)
    # Publication boundary: nothing in the repository has changed yet.
    verify_published(repo, rotation, actions, http)
    apply_rotation(repo, rotation, keys_dir)
    print(release_instructions(rotation), end="", file=sys.stderr)


# --- generation -------------------------------------------------------------


class Toolchain:
    def __init__(self, repo: Repo, work: Path):
        self.repo, self.work = repo, work
        work.mkdir(parents=True, exist_ok=True)
        self.prover = work / "light-prover"
        # A stale binary compiles a different constraint system than the
        # server; the only symptom is "invalid witness size" at proving time.
        run(["go", "build", "-o", self.prover, "."], cwd=repo.path(SERVER_REL))
        run(["cargo", "build", "-q", "-p", "xtask"], cwd=repo.root)
        target = Path(os.environ.get("CARGO_TARGET_DIR", repo.root / "target"))
        self.xtask = (target if target.is_absolute() else repo.root / target) / "debug/xtask"
        if not self.xtask.is_file():
            raise KeysError(f"cargo did not produce {self.xtask}")

    def setup(self, spec: KeySpec, destination: Path) -> None:
        # Ring setups insist on the canonical filename, so build under a
        # scratch directory and move into place only when setup succeeded.
        partial = self.work / "partial" / spec.name
        partial.parent.mkdir(parents=True, exist_ok=True)
        partial.unlink(missing_ok=True)
        command = [self.prover, *spec.setup, "--output", partial]
        if spec.writes_vkey:
            command += ["--output-vkey", self.work / f"{spec.stem}.vkey"]
        run(command, cwd=self.repo.path(SERVER_REL))
        if not partial.is_file() or partial.stat().st_size == 0:
            raise KeysError(f"setup did not produce {spec.name}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(partial, destination)

    def rust_vk(self, spec: KeySpec, key: Path, out_root: Path) -> Path:
        raw = self.work / f"{spec.stem}.vkbin"
        run([self.prover, "export-vk", "--keys-file", key, "--output", raw], cwd=self.repo.path(SERVER_REL))
        out_dir = out_root / spec.vk_path.parent
        out_dir.mkdir(parents=True, exist_ok=True)
        run([self.xtask, "bsb22-vk", raw, out_dir, spec.vk_path.name], cwd=self.repo.root)
        generated = out_dir / spec.vk_path.name
        run(["rustfmt", "--edition", "2021", "--config-path", self.repo.path("rustfmt.toml"), generated])
        return generated


def compiled_fingerprints(repo: Repo) -> dict[str, tuple[int, int]]:
    env = dict(os.environ, UPDATE_FINGERPRINTS="1")
    output = run(
        ["go", "test", "./prover/fingerprint/", "-run", "^TestCircuitFingerprintsMatchRotatedKeys$",
         "-v", "-count=1", "-timeout", "90m"],
        cwd=repo.path(SERVER_REL), env=env, capture=True,
    )
    actual = parse_fingerprints(output)
    if not actual:
        raise KeysError(f"no fingerprints in the go test output:\n{output}")
    return actual


def stage_module_lists(repo: Repo, rotation: Rotation) -> None:
    for module_dir, modules in modules_by_dir(key_table(rotation.manifest["keys"])).items():
        path = repo.path(module_dir / "mod.rs")
        current = path.read_text()
        rendered = render_module_list(current, modules)
        if rendered != current:
            rotation.stage(module_dir / "mod.rs", rendered.encode())


def new_rotation_dir(repo: Repo, out: Path | None) -> Path:
    directory = out or repo.path(ROTATIONS_REL) / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = directory.resolve()
    if (directory / PLAN_FILE).exists():
        raise KeysError(f"{directory} already holds a rotation; publish it or choose another --out")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def rotate(repo: Repo, args) -> None:
    base = repo.load_lock()
    if errors := lock_errors(base):
        raise KeysError("the committed lockfile is invalid:\n  " + "\n  ".join(errors))
    selected = select_keys(base["keys"], args.set, args.key, args.skip, args.add)
    print(f"rotating {len(selected)} key(s): {', '.join(selected)}", file=sys.stderr)
    store = None if args.no_publish else AwsStore(args.bucket)
    if store:
        store.check_credentials()

    all_names = set(base["keys"]) | set(selected)
    fingerprint_source = repo.path(FINGERPRINT_REL).read_text()
    families = fingerprint_families(parse_fingerprints(fingerprint_source), all_names)
    fingerprints = update_fingerprints(fingerprint_source, compiled_fingerprints(repo), selected, families)

    directory = new_rotation_dir(repo, args.out)
    print(f"staging in {directory}", file=sys.stderr)
    try:
        tools = Toolchain(repo, directory / "work")
        generated = {}
        for name in selected:
            spec = spec_for_name(name)
            key = directory / "keys" / name
            tools.setup(spec, key)
            tools.rust_vk(spec, key, directory / "repo")
            generated[name] = (sha256_file(key), key.stat().st_size)
        rotation = Rotation(directory, base, propose_manifest(base, generated), selected)
        rotation.staged = [str(spec_for_name(n).vk_path) for n in selected]
        stage_module_lists(repo, rotation)
        if fingerprints != fingerprint_source:
            rotation.stage(FINGERPRINT_REL, fingerprints.encode())
        rotation.stage(LOCK_REL, render_lock(rotation.manifest).encode())
        rotation.save()
        shutil.rmtree(directory / "work", ignore_errors=True)

        if store is None:
            apply_rotation(repo, rotation, args.keys_dir)
            if rotation.manifest["prefix"] != base["prefix"]:
                print(
                    f"\nThe lockfile now pins {rotation.manifest['prefix']}, which is NOT published.\n"
                    f"Publish before merging: keys.py publish {directory}",
                    file=sys.stderr,
                )
            print(release_instructions(rotation), end="", file=sys.stderr)
        else:
            # Setup can take hours; short-lived credentials may have expired.
            store.check_credentials()
            publish(repo, rotation, store, PublicHttp(), args.keys_dir)
    except BaseException:
        print(f"\nrotation stopped; staged files are kept in {directory}", file=sys.stderr)
        if (directory / PLAN_FILE).exists():
            print(f"resume with: keys.py publish {directory}", file=sys.stderr)
        raise
    added = sorted(set(selected) - set(base["keys"]))
    if added:
        print(
            f"new keys {', '.join(added)}: also extend the shape lists and VK fingerprint tests (CLAUDE.md)",
            file=sys.stderr,
        )
    print(f"rotation staged in {directory}; review and commit the repository changes", file=sys.stderr)


def migrate_release_keys(repo: Repo, args, http=None) -> Rotation:
    """Stage a new version folder that holds every key, including the
    `source: release` ones, without regenerating anything."""
    base = repo.load_lock()
    if errors := lock_errors(base):
        raise KeysError("the committed lockfile is invalid:\n  " + "\n  ".join(errors))
    released = sorted(n for n, e in base["keys"].items() if "source" in e)
    if not released:
        raise KeysError("no `source` entries left to migrate")
    directory = new_rotation_dir(repo, args.out)
    http = http or PublicHttp()
    for name in released:
        entry = base["keys"][name]
        target = directory / "keys" / name
        found = local_copy(name, entry, [args.keys_dir])
        if found:
            install_key(found, target)
            continue
        url = key_url(repo, base, name)
        print(f"downloading {url}", file=sys.stderr)
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(f".{name}.partial")
        if http.digest(url, partial) != (entry["size"], entry["sha256"]):
            partial.unlink()
            raise KeysError(f"{url} does not match the lockfile pin")
        os.replace(partial, target)
    keys = {name: {k: v for k, v in e.items() if k != "source"} for name, e in base["keys"].items()}
    rotation = Rotation(directory, base, {"keys": keys, "prefix": compute_prefix(keys)}, [])
    rotation.stage(LOCK_REL, render_lock(rotation.manifest).encode())
    rotation.save()
    print(
        f"staged {rotation.manifest['prefix']} with {len(released)} release keys in {directory}\n"
        f"publish with: keys.py publish {directory}",
        file=sys.stderr,
    )
    return rotation


def vkeys(repo: Repo, args) -> None:
    manifest = repo.load_lock()
    explicit = bool(args.set or args.key)
    names = select_keys(manifest["keys"], args.set or ["all"], args.key)
    present = [n for n in names if (args.keys_dir / n).is_file()]
    missing = sorted(set(names) - set(present))
    if explicit and missing:
        raise KeysError(f"missing in {args.keys_dir}: {', '.join(missing)}")
    if not present:
        raise KeysError(f"no pinned proving keys in {args.keys_dir}")
    work = Path(tempfile.mkdtemp(prefix="zolana-vkeys-"))
    out_root = work / "repo"
    try:
        tools = Toolchain(repo, work)
        changed = []
        for name in present:
            spec = spec_for_name(name)
            generated = tools.rust_vk(spec, args.keys_dir / name, out_root)
            target = repo.path(spec.vk_path)
            if not target.is_file() or target.read_bytes() != generated.read_bytes():
                changed.append(spec.vk_path)
                if not args.check:
                    atomic_write(target, generated.read_bytes())
        if not args.check:
            for module_dir, modules in modules_by_dir(key_table(manifest["keys"])).items():
                path = repo.path(module_dir / "mod.rs")
                atomic_write(path, render_module_list(path.read_text(), modules).encode())
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for path in changed:
        print(f"{'differs' if args.check else 'updated'}: {path}", file=sys.stderr)
    if args.check and changed:
        raise KeysError(f"{len(changed)} committed verifying key(s) are not the export of the local keys")
    print(f"{len(present)} verifying key(s) {'match' if args.check else 'regenerated'}", file=sys.stderr)


def verify(repo: Repo, args, http=None) -> None:
    http = http or PublicHttp()
    manifest = repo.load_lock()
    names = select_keys(manifest["keys"], args.set or ["all"], args.key)
    failures = 0
    for name in names:
        entry = manifest["keys"][name]
        url = key_url(repo, manifest, name)
        try:
            if args.full:
                size, digest = http.digest(url)
                if (size, digest) != (entry["size"], entry["sha256"]):
                    raise KeysError(f"served {size} bytes hashing to {digest}")
            else:
                size = http.size(url)
                if size != entry["size"]:
                    raise KeysError("missing" if size is None else f"served size {size}")
            print(f"ok      {name}", file=sys.stderr)
        except KeysError as error:
            failures += 1
            print(f"FAILED  {name}: {error} ({url})", file=sys.stderr)
    if failures:
        raise KeysError(f"{failures} of {len(names)} pinned keys failed verification")
    print(f"verified {len(names)} pinned keys ({'sha256' if args.full else 'size'})", file=sys.stderr)


# --- command line -----------------------------------------------------------


def parser(repo: Repo) -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = root.add_subparsers(dest="command", required=True)
    def absolute(value: str) -> Path:
        return Path(value).resolve()

    keys_dir = dict(type=absolute, default=repo.default_keys_dir(),
                    help="live proving-keys dir (default: $ZOLANA_SPP_KEYS_DIR or prover/server/proving-keys)")

    def selection(sub):
        sub.add_argument("--set", action="append", default=[],
                         help="all, a group (transfer, merge, batch, custom-ring) or a circuit "
                              "(transfer-ring, merge-ring, custom-ring-policy, ...); repeatable")
        sub.add_argument("--key", action="append", default=[], help="one key name, with or without .key; repeatable")

    commands.add_parser("check", help="offline consistency check of the lockfile and its derived files")

    sub = commands.add_parser("verify", help="check every pinned key is publicly served (read-only)")
    selection(sub)
    sub.add_argument("--full", action="store_true", help="download and hash instead of HEAD + size")

    sub = commands.add_parser("rotate", help="regenerate keys, VKs, fingerprints and the lockfile")
    selection(sub)
    sub.add_argument("--skip", action="append", default=[], help="drop a key from the selection; repeatable")
    sub.add_argument("--add", action="store_true", help="allow --key names the lockfile does not pin yet")
    sub.add_argument("--no-publish", action="store_true",
                     help="stage and update the repository without touching the object store")
    sub.add_argument("--out", type=absolute, help="rotation directory (default: target/proving-keys-rotation/<time>)")
    sub.add_argument("--keys-dir", **keys_dir)
    sub.add_argument("--bucket", default=os.environ.get("ZOLANA_PROVING_KEYS_BUCKET", DEFAULT_BUCKET))

    sub = commands.add_parser("publish", help="publish a staged rotation, verify it, update the repository")
    sub.add_argument("directory", type=absolute)
    sub.add_argument("--dry-run", action="store_true", help="plan from public reads only; no AWS calls")
    sub.add_argument("--keys-dir", **keys_dir)
    sub.add_argument("--bucket", default=os.environ.get("ZOLANA_PROVING_KEYS_BUCKET", DEFAULT_BUCKET))

    sub = commands.add_parser("vkeys", help="regenerate the committed Rust VKs from local proving keys")
    selection(sub)
    sub.add_argument("--check", action="store_true", help="fail on a difference instead of writing")
    sub.add_argument("--keys-dir", **keys_dir)

    sub = commands.add_parser("migrate-release-keys",
                              help="stage a version folder that also holds the `source: release` keys")
    sub.add_argument("--out", type=absolute, help="rotation directory (default: target/proving-keys-rotation/<time>)")
    sub.add_argument("--keys-dir", **keys_dir)
    return root


def main(argv=None) -> int:
    repo = Repo(REPO_ROOT)
    args = parser(repo).parse_args(argv)
    try:
        if args.command == "check":
            errors = check_repo(repo)
            if errors:
                raise KeysError("check failed:\n  " + "\n  ".join(errors))
            manifest = repo.load_lock()
            print(f"ok: {len(manifest['keys'])} keys, prefix {manifest['prefix']}", file=sys.stderr)
        elif args.command == "verify":
            verify(repo, args)
        elif args.command == "rotate":
            if not (args.set or args.key):
                raise KeysError("rotate needs --set or --key")
            rotate(repo, args)
        elif args.command == "publish":
            rotation = Rotation.load(args.directory)
            http = PublicHttp()
            if args.dry_run:
                publish(repo, rotation, PublicStore(http, repo.base_url()), http, args.keys_dir, dry_run=True)
            else:
                store = AwsStore(args.bucket)
                store.check_credentials()
                publish(repo, rotation, store, http, args.keys_dir)
        elif args.command == "vkeys":
            vkeys(repo, args)
        elif args.command == "migrate-release-keys":
            migrate_release_keys(repo, args)
    except KeysError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
