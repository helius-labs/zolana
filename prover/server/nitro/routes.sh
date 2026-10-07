#!/bin/sh
# routes.sh <key_downloader.go> <indexer-url or empty> [kms-key-arn] prints "loopback host port vsock-port" per egress origin.
set -eu

fail() {
    echo "routes: $*" >&2
    exit 1
}

keys=$(sed -n 's/^[[:space:]]*defaultProvingKeysBaseURL[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' "$1")
[ -n "$keys" ] || fail "no defaultProvingKeysBaseURL in $1"

seen=" "
index=1
route() {
    case $1 in
        https://*) ;;
        *) fail "$1 is not an https URL" ;;
    esac
    rest=${1#https://}
    authority=${rest%%[/?#]*}
    case ${rest#"$authority"} in
        *[?#]*) fail "$1 carries a query or fragment" ;;
    esac
    host=${authority%%:*}
    port=${authority#"$host"}
    port=${port#:}
    port=${port:-443}
    printf '%s\n' "$host" | grep -Eqx '([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]' \
        || fail "$1 needs a lowercase DNS host without credentials"
    if ! printf '%s\n' "$port" | grep -Eqx '[1-9][0-9]{0,4}' || [ "$port" -gt 65535 ]; then
        fail "$1 has an invalid port"
    fi
    case $seen in
        *" $host "*) fail "$host is routed twice" ;;
    esac
    seen="$seen$host "
    index=$((index + 1))
    printf '127.0.0.%s %s %s %s\n' "$index" "$host" "$port" "$((8000 + index - 1))"
}

route "$keys"
[ -z "$2" ] || route "$2"
key_arn=${3-}
if [ -n "$key_arn" ]; then
    [ "$(printf '%s\n' "$key_arn" | grep -Ex 'arn:aws:kms:[a-z]{2}(-[a-z]+)+-[0-9]+:[0-9]{12}:key/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}')" = "$key_arn" ] \
        || fail "$key_arn is not a KMS key ARN"
    region=${key_arn#arn:aws:kms:}
    route "https://kms.${region%%:*}.amazonaws.com"
fi
