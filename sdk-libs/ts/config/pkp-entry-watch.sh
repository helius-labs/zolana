#!/usr/bin/env bash
# Wake the coordinator when the cryptographic certification phase may begin.
#
# The phase after the review is large, and the handover between them is a person
# noticing that the review finished. That person is the bottleneck and is often
# asleep. This polls the entry gate instead and emits a sentinel the moment all
# four criteria hold, so the next phase starts when the work is ready rather than
# when someone looks.
#
# Exit code 2 from the gate means it could not decide, usually because GitHub was
# unreachable. That is not a refusal and must not be reported as one, so the
# watcher stays quiet and tries again.
#
#   sdk-libs/ts/config/pkp-entry-watch.sh [interval-seconds]

set -uo pipefail

interval="${1:-600}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
gate="$root/sdk-libs/ts/config/pkp-entry-gate.mjs"

undecided_streak=0

while true; do
  summary="$(cd "$root" && node "$gate" --json 2>/dev/null)"
  case $? in
    0)
      echo "AGENT_LOOP_WAKE_pkp {\"prompt\":\"The cryptographic certification entry gate passes. Confirm it independently, then start PKP-00 from planning/typescript-sdk-port/proof-and-key-parity.md.\"}"
      exit 0
      ;;
    1)
      undecided_streak=0
      # Report the shortfall so a watcher log reads as progress rather than as a
      # row of identical refusals.
      echo "pkp-gate $(date +%H:%M:%S) not ready: $(echo "$summary" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const g=JSON.parse(s);console.log(g.criteria.filter(c=>!c.pass).map(c=>c.detail).join(" | "))}catch{console.log("unparseable")}})')"
      ;;
    *)
      undecided_streak=$((undecided_streak + 1))
      # Undecidable once is a network blip. Undecidable repeatedly means the gate
      # itself is broken, and a silent watcher would hide that indefinitely.
      if [ "$undecided_streak" -ge 5 ]; then
        echo "AGENT_LOOP_WAKE_pkp {\"prompt\":\"The cryptographic entry gate has failed to evaluate ${undecided_streak} times in a row. Diagnose the gate itself; do not assume the phase is blocked.\"}"
        exit 2
      fi
      echo "pkp-gate $(date +%H:%M:%S) undecided (${undecided_streak}/5)"
      ;;
  esac
  sleep "$interval"
done
