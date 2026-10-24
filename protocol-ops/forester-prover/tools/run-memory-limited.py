#!/usr/bin/env python3
"""Run an already-built native proof command with an aggregate RSS watchdog."""
import argparse
import json
import os
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path


class MonitorInterrupted(RuntimeError):
    """A stop request that subprocess wait cannot mistake for a retryable EINTR."""


def kill_group(child, signum):
    try:
        os.killpg(child.pid, signum)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin can reject a second group signal while a killed group exits.
        # Popen reaps an exited direct child before trying another signal.
        child.send_signal(signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit-bytes", type=int, default=10_000_000_000)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    command = options.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or options.limit_bytes <= 0:
        parser.error("a positive memory limit and proof command are required")
    started = time.monotonic()
    child = None
    maximum = 0
    exceeded = False
    samples = 0
    monitor_error = None
    exit_code = 1

    def interrupted(signum, frame):
        raise MonitorInterrupted("memory monitor received signal " + str(signum))

    previous = {
        signum: signal.signal(signum, interrupted)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        child = subprocess.Popen(command, start_new_session=True)
        while child.poll() is None:
            snapshot = subprocess.run(
                ["ps", "-axo", "pid=,ppid=,rss="],
                check=True, capture_output=True, text=True, timeout=5,
            ).stdout
            processes = []
            for line in snapshot.splitlines():
                try:
                    pid, parent, rss = map(int, line.split())
                except ValueError:
                    continue
                processes.append((pid, parent, rss * 1024))
            owned = {child.pid}
            while True:
                expanded = owned | {pid for pid, parent, _ in processes if parent in owned}
                if expanded == owned:
                    break
                owned = expanded
            resident = sum(rss for pid, _, rss in processes if pid in owned)
            maximum = max(maximum, resident)
            samples += 1
            if resident >= options.limit_bytes:
                exceeded = True
                kill_group(child, signal.SIGKILL)
                break
            time.sleep(0.05)
    except BaseException as error:
        monitor_error = str(error)
    finally:
        # A failed or interrupted monitor must not leave an unguarded proof running.
        for signum in previous:
            signal.signal(signum, signal.SIG_IGN)
        if child is not None:
            if child.poll() is None:
                kill_group(child, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    kill_group(child, signal.SIGKILL)
            exit_code = child.wait()
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        kernel_maximum = int(usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024))
        sampled_maximum = maximum
        maximum = max(maximum, kernel_maximum)
        exceeded = exceeded or maximum >= options.limit_bytes
        report = {
            "command": command, "pid": child.pid if child else None,
            "exitCode": exit_code, "monitorError": monitor_error,
            "elapsedSeconds": time.monotonic() - started,
            "limitBytes": options.limit_bytes, "peakResidentBytes": maximum,
            "sampledPeakResidentBytes": sampled_maximum if samples else None,
            "kernelChildPeakResidentBytes": kernel_maximum, "samples": samples,
            "memoryLimitExceeded": exceeded, "platform": sys.platform,
        }
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), file=sys.stderr, flush=True)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if exceeded or monitor_error:
        return 1
    return exit_code if exit_code >= 0 else 128 - exit_code


if __name__ == "__main__":
    raise SystemExit(main())
