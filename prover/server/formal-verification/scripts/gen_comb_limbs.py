#!/usr/bin/env python3
"""Generate VerifiableEncryption/Curve/CombLimbs.lean.

The extracted `scalarMulBase` passes every comb window table to `combSelect`
as limb constants at the call site: 51 calls of the 32-entry packed-y select
and one call of the 4-entry top-window select, in window order. This script
copies those table arguments verbatim out of VerifiableEncryption/Circuit/Curve.lean,
so `txs`, `tys`, `topX` and `topY` are the exact terms the circuit uses. Any
other number of calls aborts generation.

Usage (from prover/server/formal-verification):
  scripts/gen_comb_limbs.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "VerifiableEncryption/Circuit/Curve.lean"
OUT = ROOT / "VerifiableEncryption/Curve/CombLimbs.lean"

WINDOW = re.compile(r"^    CombSelect_8_32_3_32_5_h[0-9a-f]{8} (vec!.*)$", re.M)
TOP = re.compile(r"^    CombSelect_8_4_8_4_2_h[0-9a-f]{8} (vec!.*)$", re.M)
WINDOWS = 51

HEADER = """import VerifiableEncryption.Field.Layout

/-!
The constant comb tables exactly as the extracted `scalarMulBase` passes
them to `combSelect`: x limbs and packed y limb groups per window entry.
Generated from `Circuit/Curve.lean`.
-/

namespace ZolanaVE.CombLimbs

set_option maxRecDepth 100000

"""


def leading_vectors(text, count):
    """Split the first `count` balanced `vec![...]` arguments off `text`."""
    out = []
    pos = 0
    for _ in range(count):
        if not text.startswith("vec![", pos):
            sys.exit(f"expected a vec! argument at {text[pos:pos + 40]!r}")
        depth = 0
        for end in range(pos, len(text)):
            if text[end] == "[":
                depth += 1
            elif text[end] == "]":
                depth -= 1
                if depth == 0:
                    break
        else:
            sys.exit("unbalanced vec! argument")
        out.append(text[pos:end + 1])
        pos = end + 2
    return out


def main():
    src = SRC.read_text()
    windows = [leading_vectors(m.group(1), 2) for m in WINDOW.finditer(src)]
    tops = [leading_vectors(m.group(1), 2) for m in TOP.finditer(src)]
    if len(windows) != WINDOWS or len(tops) != 1:
        sys.exit(f"found {len(windows)} window selects and {len(tops)} top selects, want {WINDOWS} and 1")
    lines = []
    for t, (tx, ty) in enumerate(windows):
        lines.append(f"def tx{t} : List.Vector (List.Vector F 8) 32 := {tx}")
        lines.append(f"def ty{t} : List.Vector (List.Vector F 3) 32 := {ty}")
    top_x, top_y = tops[0]
    lines.append(f"def topX : List.Vector (List.Vector F 8) 4 := {top_x}")
    lines.append(f"def topY : List.Vector (List.Vector F 8) 4 := {top_y}")
    names_x = ", ".join(f"tx{t}" for t in range(WINDOWS))
    names_y = ", ".join(f"ty{t}" for t in range(WINDOWS))
    out = (HEADER + "\n".join(lines) + "\n\n"
           + f"def txs : List (List.Vector (List.Vector F 8) 32) := [{names_x}]\n"
           + f"def tys : List (List.Vector (List.Vector F 3) 32) := [{names_y}]\n\n"
           + "end ZolanaVE.CombLimbs\n")
    OUT.write_text(out)


if __name__ == "__main__":
    main()
