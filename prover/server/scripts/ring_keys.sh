# The custom-ring proving keys, the release assets the lockfile pins.
ring_keys=()
while read -r key; do
    ring_keys+=("$key")
done < <(python3 -c 'import json, sys; print("\n".join(k for k, v in json.load(open(sys.argv[1]))["keys"].items() if v.get("source") == "release"))' \
    "$(dirname "${BASH_SOURCE[0]}")/../prover/provingkeys/proving-keys.lock")
