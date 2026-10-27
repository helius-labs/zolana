#!/usr/bin/env python3
"""Migrate the legacy ring fixture's SDK references before compatibility tests."""

import re
import subprocess
import sys
import tomllib
from pathlib import Path


def migrate(sdk_root: Path, ring_root: Path) -> None:
    sdk = tomllib.loads((sdk_root / "Cargo.toml").read_text())
    dependencies = sdk["workspace"]["dependencies"]
    names = {name for name in dependencies if name.startswith("spr-")}
    for member in sdk["workspace"]["members"]:
        package = tomllib.loads((sdk_root / member / "Cargo.toml").read_text())
        name = package["package"]["name"]
        if name.startswith("spr-"):
            names.add(name)
    replacements = {name.replace("spr-", "zolana-", 1): name for name in names}
    replacements.update(
        {old.replace("-", "_"): new.replace("-", "_") for old, new in list(replacements.items())}
    )
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])(?:"
        + "|".join(re.escape(name) for name in sorted(replacements, key=len, reverse=True))
        + r")(?![A-Za-z0-9_-])"
    )
    ring_manifest = ring_root / "Cargo.toml"
    original = tomllib.loads(ring_manifest.read_text())
    revisions = {
        original["workspace"]["dependencies"][old]["rev"]: dependencies[new]["rev"]
        for old, new in replacements.items()
        if new.startswith("spr-zk-")
        and old in original["workspace"]["dependencies"]
        and "rev" in original["workspace"]["dependencies"][old]
    }
    tracked = subprocess.check_output(["git", "-C", str(ring_root), "ls-files", "-z"])
    changed = 0
    for filename in tracked.decode().split("\0"):
        path = ring_root / filename
        if not filename or not path.is_file() or path.name.endswith(".lock"):
            continue
        try:
            source = path.read_text()
        except UnicodeDecodeError:
            continue
        migrated = pattern.sub(lambda match: replacements[match[0]], source)
        for old, new in revisions.items():
            migrated = migrated.replace(old, new)
        if migrated != source:
            path.write_text(migrated)
            changed += 1
    print(f"Migrated SDK crate references in {changed} ring fixture files")


if __name__ == "__main__":
    migrate(Path(__file__).resolve().parents[2], Path(sys.argv[1]).resolve())
