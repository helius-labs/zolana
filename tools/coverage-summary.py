#!/usr/bin/env python3
"""Render a cargo-llvm-cov JSON export as a GitHub job-summary markdown table.

Usage: coverage-summary.py <llvm-cov-json> [least-covered-count]

Reads the `--json --summary-only` export (llvm-cov's own export format, which
cargo-llvm-cov passes through) and writes markdown to stdout. Paths are printed
relative to the repository root so the table stays readable.
"""

import json
import os
import sys

METRICS = (("Lines", "lines"), ("Regions", "regions"), ("Functions", "functions"))


def pct(entry):
    """llvm-cov reports `percent` only when count > 0; treat empty as fully covered."""
    return entry["percent"] if entry["count"] else 100.0


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} <llvm-cov-json> [least-covered-count]")
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    with open(path) as handle:
        report = json.load(handle)
    export = report["data"][0]
    totals = export["totals"]

    out = ["## Coverage", ""]
    out.append("| Metric | Covered | Total | % |")
    out.append("| --- | ---: | ---: | ---: |")
    for label, key in METRICS:
        entry = totals[key]
        out.append(
            f"| {label} | {entry['covered']:,} | {entry['count']:,} | {pct(entry):.2f}% |"
        )
    out.append("")

    root = os.getcwd() + os.sep
    files = [f for f in export.get("files", []) if f["summary"]["lines"]["count"]]
    files.sort(key=lambda f: (pct(f["summary"]["lines"]), -f["summary"]["lines"]["count"]))

    if files:
        shown = files[:limit]
        out.append(
            f"<details><summary>{len(shown)} least-covered files "
            f"(of {len(files)})</summary>"
        )
        out.append("")
        out.append("| File | Lines | Covered | % |")
        out.append("| --- | ---: | ---: | ---: |")
        for entry in shown:
            lines = entry["summary"]["lines"]
            name = entry["filename"]
            if name.startswith(root):
                name = name[len(root) :]
            out.append(
                f"| `{name}` | {lines['count']:,} | {lines['covered']:,} "
                f"| {pct(lines):.2f}% |"
            )
        out.append("")
        out.append("</details>")
        out.append("")

    out.append(
        "The full browsable HTML report and `lcov.info` are attached to this run "
        "as build artifacts."
    )
    print("\n".join(out))


if __name__ == "__main__":
    main()
