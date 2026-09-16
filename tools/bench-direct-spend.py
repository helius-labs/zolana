#!/usr/bin/env python3
"""Run cached, direct, GKR and admitted localnet benchmarks sequentially."""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-worktree", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--cache-target-dir", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--photon", type=Path, required=True)
    parser.add_argument("--gkr-prover", type=Path, required=True)
    parser.add_argument("--cache-prover", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--routes", nargs="+", choices=["cached", "direct", "gkr", "admitted", "admitted-dag10"], default=["cached", "direct", "gkr", "admitted"])
    parser.add_argument("--profile", choices=["dev", "release"], default="dev")
    parser.add_argument("--inputs", nargs="+", type=int, default=[144, 512])
    parser.add_argument("--states", nargs="+", choices=["cold", "warm"], default=["warm"])
    parser.add_argument("--layouts", nargs="+", choices=["clustered", "interleaved"], default=["interleaved"])
    parser.add_argument("--paired", action="store_true", help="Measure the first paid spend as cold and the next fresh spend as warm")
    parser.add_argument("--runs", type=int, default=int(os.environ.get("E2E_BENCH_RUNS", "3")))
    args = parser.parse_args()
    if args.paired:
        args.states = ["warm"]
    if args.runs < 1 or any(count < 1 or count > 512 for count in args.inputs):
        parser.error("runs must be positive and input counts must be within 1..512")
    for name in ["cache_worktree", "target_dir", "cache_target_dir", "cli", "photon", "gkr_prover", "cache_prover", "output"]:
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=True)
    if any(args.output.iterdir()):
        parser.error("output directory must be empty so benchmark samples cannot be mixed")
    binaries = {
        "cli": args.cli,
        "photon": args.photon,
        "gkr_prover": args.gkr_prover,
        "cache_prover": args.cache_prover,
        "gkr_program": root / "target/deploy/shielded_pool_program.so",
        "cache_program": args.cache_worktree / "target/deploy/shielded_pool_program.so",
        "surfpool": root / "target/tools/surfpool",
    }
    for name, workspace in [("gkr", root), ("cache", args.cache_worktree)]:
        for program in ["squads_smart_account_program", "zolana_user_registry"]:
            binaries[f"{name}_{program}"] = workspace / "target/deploy" / f"{program}.so"
    for path in binaries.values():
        if not path.is_file():
            parser.error(f"missing required artifact: {path}")
    settings = {
        "GOMAXPROCS": os.environ.get("GOMAXPROCS", "18"),
        "GOMEMLIMIT": os.environ.get("GOMEMLIMIT", "24GiB"),
        "PROVER_SYNC_CONCURRENCY": os.environ.get("PROVER_SYNC_CONCURRENCY", "4"),
        "E2E_BENCH_CONCURRENCY": os.environ.get("E2E_BENCH_CONCURRENCY", "4"),
        "E2E_BENCH_POLL_MS": os.environ.get("E2E_BENCH_POLL_MS", "25"),
        "E2E_BENCH_INDEXER_POLL_MS": os.environ.get("E2E_BENCH_INDEXER_POLL_MS", "500"),
        "E2E_BENCH_OVERLAP": os.environ.get("E2E_BENCH_OVERLAP", "1"),
        "E2E_BENCH_CHUNKED": os.environ.get("E2E_BENCH_CHUNKED", "1"),
        "E2E_BENCH_INSTRUCTION_PROFILING": os.environ.get("E2E_BENCH_INSTRUCTION_PROFILING", "0"),
        "E2E_BENCH_SETUP_CONCURRENCY": os.environ.get("E2E_BENCH_SETUP_CONCURRENCY", "8"),
        "E2E_BENCH_PREPARED": "0",
        "E2E_BENCH_PACKED": "1",
    }
    manifest = {
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "logical_cpus": os.cpu_count(),
        "settings": settings,
        "native_profile": args.profile,
        "runs": args.runs,
        "paired_cold_warm": args.paired,
        "artifacts": {name: {"path": str(path), "sha256": digest(path)} for name, path in binaries.items()},
        "cases": [],
    }
    rows = []
    with open("/private/tmp/zolana-direct-spend-bench.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for layout in args.layouts:
            for inputs in args.inputs:
                for state in args.states:
                    for route in args.routes:
                        workspace = args.cache_worktree if route == "cached" else root
                        label = f"{route}-{inputs}-{state}-{layout}"
                        env = os.environ | settings | {
                            "CARGO_TARGET_DIR": str(args.cache_target_dir if route == "cached" else args.target_dir),
                            "DEVELOPER_DIR": os.environ.get("DEVELOPER_DIR", "/Library/Developer/CommandLineTools"),
                            "SHIELDED_POOL_PROGRAM_ID": os.environ.get("SHIELDED_POOL_PROGRAM_ID", "sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6"),
                            "ZOLANA_CLI_BIN": str(args.cli),
                            "ZOLANA_PHOTON_BIN": str(args.photon),
                            "ZOLANA_PROVER_BIN": str(args.cache_prover if route == "cached" else args.gkr_prover),
                            "ZOLANA_LOCALNET_RPC_PORT": "9399",
                            "ZOLANA_LOCALNET_PHOTON_PORT": "9284",
                            "ZOLANA_LOCALNET_URL": "http://127.0.0.1:9399",
                            "ZOLANA_INDEXER_URL": "http://127.0.0.1:9284",
                            "ZOLANA_PROVER_URL": "http://127.0.0.1:3301",
                            "E2E_BENCH_MODE": route,
                            "E2E_BENCH_INPUTS": str(inputs),
                            "E2E_BENCH_RUNS": str(args.runs),
                            "E2E_BENCH_WARM_KEYS": str(int(state == "warm")),
                            "E2E_BENCH_LAYOUT": layout,
                        }
                        env.pop("PROVER_BIN", None)
                        env.pop("ZOLANA_PROVER_KEYS_DIR", None)
                        command = ["cargo", "test", "--offline", "-j2", "--profile", args.profile]
                        if route == "cached":
                            command += ["-p", "spp-test-validator", "--test", "proof_cu", "cached_merge_spend_e2e_benchmark"]
                        else:
                            command += ["-p", "shielded-pool-tests", "--features", "localnet,proofs", "--test", "direct_spend_localnet", "direct_spend_e2e_benchmark"]
                        command += ["--", "--ignored", "--nocapture", "--test-threads=1"]
                        print(f"Running {label}: {args.runs} measured samples", flush=True)
                        case = {"label": label, "workspace": str(workspace), "command": command}
                        manifest["cases"].append(case)
                        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
                        measured = 0
                        cold = 0
                        with (args.output / f"{label}.log").open("w") as log:
                            process = subprocess.Popen(command, cwd=workspace, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                            for line in process.stdout:
                                log.write(line)
                                log.flush()
                                if line.startswith(("E2E_PIPELINE ", "BENCH_PROVER ")):
                                    print(line.rstrip(), flush=True)
                                if line.startswith("E2E_PIPELINE "):
                                    row = json.loads(line.removeprefix("E2E_PIPELINE "))
                                    row["case"] = label
                                    rows.append(row)
                                    measured += row.get("phase") == "measured"
                                    cold += row.get("key_state") == "cold"
                                    with (args.output / "samples.jsonl").open("a") as results:
                                        results.write(json.dumps(row) + "\n")
                                    package = "spp-test-validator" if route == "cached" else "shielded-pool"
                                    prover_log = workspace / "program-tests" / package / "test-ledger/prover-server.log"
                                    if prover_log.is_file():
                                        shutil.copyfile(prover_log, args.output / f"{label}-{row['run']}-{row['phase']}-prover.log")
                            status = process.wait()
                        case["exit_code"] = status
                        case["measured_samples"] = measured
                        case["cold_samples"] = cold
                        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
                        if status or measured != args.runs or cold != args.runs:
                            raise SystemExit(f"{label} failed or produced incomplete samples; see its log")
    groups = {}
    for row in rows:
        if row["phase"] != "measured" and not args.paired:
            continue
        label = f"{row['variant']}-{row['inputs']}-{row['key_state']}-{row['layout']}"
        groups.setdefault(label, []).append(row)
    summary = []
    for label, samples in groups.items():
        if len(samples) != args.runs:
            raise SystemExit(f"{label} has incomplete samples")
        summary.append({"case": label, "samples": len(samples), **{
            field: {"median": statistics.median(row[field] for row in samples), "min": min(row[field] for row in samples), "max": max(row[field] for row in samples)}
            for field in ["witness_ms", "prove_ms", "submit_ms", "total_ms", "total_cu", "transactions"]
        }})
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
