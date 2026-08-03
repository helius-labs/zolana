#!/usr/bin/env python3
"""Emit the `-p <name>` flags selecting which crates `just coverage` measures.

Selection is by manifest PATH, not by crate name, so renaming or adding a crate
cannot silently change what is covered. Naming the harness crates individually is
what broke before: #181 renamed `zone-test-program` to `ring-test-program`, the
stale `--exclude zone-test-program` stopped matching, and a test crate quietly
entered the coverage set and failed the job.

Everything under `EXCLUDED_DIRS` is left out; every other workspace member is
covered, so a new library crate is measured the day it lands.
"""

import json
import os
import subprocess
import sys

# Directories whose crates are never measured.
#
#   programs/      on-chain programs. Their logic runs inside the SVM under
#                  litesvm/mollusk, which llvm-cov (a host-build instrumenter)
#                  cannot see, and their host-side unit tests live in
#                  program-tests. Measuring them reports ~0% for code that is
#                  in fact well covered, just not by this tool.
#   program-tests/ the harness and the SBF fixture programs it drives.
#   sdk-tests/     example programs and their SDK/prover scaffolding.
#   bench/         CU benchmarks, which run under `--ignored` and need SBF builds.
#   xtask/         `publish = false` build and release automation (the
#                  cargo-xtask pattern), not a shipped artifact. Same blind spot
#                  as programs/: what exercises it is being RUN -- the justfile's
#                  `cargo run -p xtask -- program-ids` and the verifying-keys
#                  smoke job -- as a subprocess this job cannot instrument. It
#                  measured 4.78% of 1,902 lines, all of it create_release.rs's
#                  unit tests, while main.rs / init_protocol.rs /
#                  update_protocol_config.rs sat permanently at 0% and occupied
#                  the top of the least-covered list ahead of files that should
#                  actually move.
EXCLUDED_DIRS = ("programs", "program-tests", "sdk-tests", "bench", "xtask")

# Collected by a separate `--lib` pass: this crate's integration targets declare
# no required-features, so selecting the whole package would build and run the
# proving suites, which need a live prover server.
SEPARATE_PASS = ("zolana-client",)


def main():
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            capture_output=True,
            check=True,
            text=True,
        ).stdout
    )
    root = meta["workspace_root"]

    selected = []
    for package in meta["packages"]:
        rel = os.path.relpath(package["manifest_path"], root)
        if rel.split(os.sep)[0] in EXCLUDED_DIRS:
            continue
        if package["name"] in SEPARATE_PASS:
            continue
        selected.append(package["name"])

    if not selected:
        sys.exit("coverage-packages: selected no crates; check EXCLUDED_DIRS")

    print(" ".join(f"-p {name}" for name in sorted(selected)))


if __name__ == "__main__":
    main()
