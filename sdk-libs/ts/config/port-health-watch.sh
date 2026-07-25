#!/usr/bin/env bash
# Wake the coordinator when the port's health changes for the worse.
#
# The loops this replaces fired on a timer and asked for a status update whether
# or not anything had happened, so most wakes reported that nothing had changed
# and the ones that mattered read the same as the ones that did not. This runs
# the health check instead and stays silent while the answer holds steady.
#
# Silence is the point. A wake means a problem appeared that was not there
# before: an agent stopped writing, the checklist fell behind the row updates
# feeding it, a worker branch was left unmerged, or the plan's numbers stopped
# describing the branch. Problems already reported stay quiet until they clear,
# because a watcher that repeats itself gets ignored, and a watcher that gets
# ignored is worse than none.
#
#   sdk-libs/ts/config/port-health-watch.sh [interval-seconds]

set -uo pipefail

interval="${1:-300}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
state="${TMPDIR:-/tmp}/zolana-port-health-seen"

: >"$state"

while true; do
  sleep "$interval"

  report="$(cd "$root" && node sdk-libs/ts/config/port-health.mjs --json 2>/dev/null)"
  if [ -z "$report" ]; then
    # A check that cannot run has not found the port healthy. Say so rather than
    # letting an empty result read as silence.
    echo "port-health $(date +%H:%M:%S) could not run"
    continue
  fi

  # Compare against what was already reported so a standing problem does not
  # wake anyone twice, while a new one wakes them immediately.
  fresh="$(echo "$report" | node -e '
    const fs = require("fs");
    let raw = "";
    process.stdin.on("data", (chunk) => (raw += chunk)).on("end", () => {
      const seen = new Set(
        fs.readFileSync(process.argv[1], "utf8").split("\n").filter(Boolean),
      );
      let problems = [];
      try {
        problems = JSON.parse(raw).problems ?? [];
      } catch {
        process.exit(0);
      }
      // Quiet times and byte counts drift every run; comparing on them would
      // make each poll look new. Compare on the part that names the problem.
      const key = (text) => text.replace(/\d+/g, "#");
      const novel = problems.filter((text) => !seen.has(key(text)));
      fs.writeFileSync(process.argv[1], problems.map(key).join("\n"));
      if (novel.length > 0) console.log(novel.join(" | "));
    });
  ' "$state")"

  if [ -n "$fresh" ]; then
    escaped="${fresh//\"/\\\"}"
    echo "AGENT_LOOP_WAKE_health {\"prompt\":\"The port health check found something new: ${escaped}. Confirm it independently before acting, because transcript writes lag and a quiet agent may still be committing. Then fix what is real: relaunch dead agents after salvaging their worktrees, dispatch the reconciler if the checklist is behind, merge and gate any finished branch, and refresh the plan's status block. Report what you found and what you changed.\"}"
  else
    echo "port-health $(date +%H:%M:%S) no change"
  fi
done
