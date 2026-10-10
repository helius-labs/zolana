#!/usr/bin/env python3
"""Regenerate the import block of VerifiableEncryption.lean.

Every module under VerifiableEncryption/ is imported, sorted, so the root
elaborates the whole library. The rest of the root file (restated theorems and
the pinned axiom sets) is kept as written between the markers.

Usage (from prover/server/formal-verification):
  scripts/gen_ve_root.py
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "VerifiableEncryption"
OUT = ROOT / "VerifiableEncryption.lean"
MARK = "-- end of generated imports"


def main():
    mods = sorted(
        "VerifiableEncryption." + ".".join(p.relative_to(LIB).with_suffix("").parts)
        for p in LIB.rglob("*.lean")
    )
    imports = "".join(f"import {m}\n" for m in mods)
    rest = OUT.read_text().split(MARK + "\n", 1)[1] if OUT.exists() else "\n"
    OUT.write_text(imports + MARK + "\n" + rest)


if __name__ == "__main__":
    main()
