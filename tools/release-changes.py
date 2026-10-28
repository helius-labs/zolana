#!/usr/bin/env python3
"""Select deployable services affected by a main-branch change."""
import json
import subprocess
import sys


def changed_services(paths):
    paths = set(paths)
    shared = any(p.startswith(("program-libs/", ".cargo/")) or p in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "tools/images.json"} for p in paths)
    workflow = any(p.startswith(".github/workflows/publish-") or p == "tools/release-changes.py" for p in paths)
    photon = shared or workflow or any(p == "tools/check-photon-image.sh" or p.startswith(("services/photon/", "sdk-libs/event/", "sdk-libs/indexer-api/")) for p in paths)
    forester = shared or workflow or any(p.startswith("forester/") for p in paths)
    prover = workflow or any(p.startswith("prover/server/") for p in paths)
    measured = any(p.startswith('prover/server/') and not p.endswith(('.md','_test.go')) and '/testdata/' not in p and '/scripts/' not in p for p in paths)
    nitro = measured or '.github/workflows/publish-nitro.yml' in paths
    return {"services": [s for s, changed in (("photon", photon), ("forester", forester), ("prover", prover)) if changed], "nitro": nitro}


if __name__ == "__main__":
    before, after = sys.argv[1:]
    if set(before) == {"0"}:
        paths = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", after], text=True).splitlines()
    else:
        paths = subprocess.check_output(["git", "diff", "--name-only", before, after], text=True).splitlines()
    print(json.dumps(changed_services(paths)))
