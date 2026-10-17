#!/usr/bin/env bash
# Succeeds when COMMIT is on main or on a release/* branch: the lines a release
# image may be built from. A release/* branch carries a stack's pinned program
# compatibility (release/devnet-c is main without changes the deployed program
# cannot run yet), and is guarded like main by enforce-pr-only.
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "Usage: $0 COMMIT" >&2
    exit 2
fi
git fetch --no-tags origin \
    '+refs/heads/main:refs/remotes/origin/main' \
    '+refs/heads/release/*:refs/remotes/origin/release/*'
for line in origin/main $(git for-each-ref --format='%(refname:short)' refs/remotes/origin/release/); do
    if git merge-base --is-ancestor "$1" "$line"; then
        echo "$1 is on $line"
        exit 0
    fi
done
echo "$1 is on neither main nor a release/* branch" >&2
exit 1
