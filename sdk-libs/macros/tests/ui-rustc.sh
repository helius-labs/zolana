#!/bin/sh
set -eu

for arg do
    case "$arg" in
        */git/checkouts/*/zk-dsl/*)
            exec "$@" "--remap-path-prefix=${arg%%/zk-dsl/*}=/zk-tools"
            ;;
    esac
done

exec "$@"
