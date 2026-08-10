#!/usr/bin/env python3
"""Parse `go test -bench` output from bench_gpu.sh into JSON rows.

The benchmark name and its result print on separate lines when the prover
logs between them, so the parser carries the last seen name forward.
"""
import json
import platform
import re
import sys

NAME = re.compile(
    r"^BenchmarkProve(?:Transfer|Merge)/(?P<backend>cpu|gpu)/(?P<circuit>[\w-]+)/"
    r"inputs_(?P<inputs>\d+)_outputs_(?P<outputs>\d+)-\d+"
)
RESULT = re.compile(r"^\s*(?P<iters>\d+)\s+(?P<ns>\d+(?:\.\d+)?) ns/op(?P<metrics>.*)$")
METRIC = re.compile(r"(\d+(?:\.\d+)?)\s+([\w/]+)")


def main(path: str) -> None:
    rows = []
    pending = None
    for raw in open(path, encoding="utf-8", errors="replace"):
        m = NAME.match(raw)
        if m:
            pending = m
            continue
        r = RESULT.match(raw)
        if not (r and pending):
            continue
        row = {
            "backend": pending["backend"],
            "circuit": pending["circuit"],
            "n_inputs": int(pending["inputs"]),
            "n_outputs": int(pending["outputs"]),
            "iters": int(r["iters"]),
            "warm_ms": round(float(r["ns"]) / 1e6, 3),
            "host": platform.node(),
        }
        for value, unit in METRIC.findall(r["metrics"]):
            if unit == "constraints":
                row["constraints"] = int(float(value))
            elif unit == "cold_ms":
                row["cold_ms"] = round(float(value), 1)
        rows.append(row)
        pending = None
    json.dump(rows, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main(sys.argv[1])
