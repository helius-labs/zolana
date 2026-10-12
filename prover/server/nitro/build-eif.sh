#!/usr/bin/env bash
# build-eif.sh <image@sha256:digest> <out-dir>
#
# Builds the Nitro enclave image file of a pulled prover image with the pinned
# nitro-cli in the pinned Amazon Linux 2023 container `tools/nitro/aws_nitro.py
# measure` uses, so the PCRs match a measure of the same digest. Writes
# <out-dir>/prover.eif and <out-dir>/measurements.json, which
# `xtask tee-policy --expect-pcrs` reads and the Nitro host configures its
# egress from.
set -euo pipefail

builder=amazonlinux:2023@sha256:8ed3c0a996841537f75607e7d1de2114d8150391f75792e8da9268738547e73f
nitro_cli=1.5.0-0.amzn2023

[[ $# -eq 2 ]] || { echo "usage: $0 <image@sha256:digest> <out-dir>" >&2; exit 1; }
image=$1
[[ $image =~ @sha256:[0-9a-f]{64}$ ]] || { echo "$image must be pinned by digest" >&2; exit 1; }
mkdir -p "$2"
out=$(cd "$2" && pwd)

docker image inspect "$image" > /dev/null
docker run --rm --platform linux/amd64 \
    -v /var/run/docker.sock:/var/run/docker.sock -v "$out:/out" \
    -e IMAGE="$image" -e NITRO_CLI="$nitro_cli" "$builder" sh -ec '
        dnf install -y -q "aws-nitro-enclaves-cli-$NITRO_CLI" "aws-nitro-enclaves-cli-devel-$NITRO_CLI" > /dev/null
        export NITRO_CLI_ARTIFACTS=/tmp/nitro-artifacts
        mkdir -p "$NITRO_CLI_ARTIFACTS"
        nitro-cli build-enclave --docker-uri "$IMAGE" --output-file /out/prover.eif > /out/build.json
        nitro-cli describe-eif --eif-path /out/prover.eif > /out/describe.json
    '

# The image's egress routes and indexer URL, which the host needs and cannot read
# from the EIF.
image_file() { docker run --rm --platform linux/amd64 --entrypoint cat "$image" "/etc/zolana-nitro/$1"; }
kms_key=$(image_file kms-key)
indexer_url=$(image_file indexer-url)
routes=$(image_file routes)
jq -n \
    --slurpfile built "$out/build.json" \
    --slurpfile described "$out/describe.json" \
    --arg image "$image" \
    --arg nitro_cli "$nitro_cli" \
    --arg kms_key "$kms_key" \
    --arg indexer_url "$indexer_url" \
    --arg routes "$routes" \
    --arg eif_sha256 "$(sha256sum "$out/prover.eif" | cut -d' ' -f1)" '
    ($built[0].Measurements) as $b | ($described[0].Measurements) as $d |
    if [$b.PCR0, $b.PCR1, $b.PCR2] != [$d.PCR0, $d.PCR1, $d.PCR2]
    then error("describe-eif disagrees with build-enclave") else . end |
    {
        PCR0: $d.PCR0, PCR1: $d.PCR1, PCR2: $d.PCR2, HashAlgorithm: $d.HashAlgorithm,
        image: $image, nitro_cli: $nitro_cli, kms_key: (if $kms_key == "" then null else $kms_key end),
        indexer_url: $indexer_url, routes: ($routes | split("\n") | map(select(. != ""))),
        eif_sha256: $eif_sha256, source: "measure"
    }' > "$out/measurements.json"
rm "$out/build.json" "$out/describe.json"
cat "$out/measurements.json"
