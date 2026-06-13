#!/usr/bin/env bash

set -euo pipefail

root=$(git rev-parse --show-toplevel)
sbf_tools_version="${SBF_TOOLS_VERSION:-v1.54}"
state_dir="${ZOLANA_LOCALNET_STATE_DIR:-$root/target/localnet}"
rpc_port="${ZOLANA_LOCALNET_RPC_PORT:-8899}"
faucet_port="${ZOLANA_LOCALNET_FAUCET_PORT:-9900}"
launchd_label="${ZOLANA_LOCALNET_LAUNCHD_LABEL:-com.zolana.localnet}"
shielded_pool_program_id="S7exd9VLhvwVWK9wqRGQrg87616fGnyYEvrsuA1D2LG"
zone_test_program_id="9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz"

if [[ "$state_dir" != /* ]]; then
    state_dir="$root/$state_dir"
fi

rpc_url="http://127.0.0.1:${rpc_port}"
ledger="$state_dir/ledger"
pid_file="$state_dir/validator.pid"
label_file="$state_dir/validator.label"
log_file="$state_dir/validator.log"

usage() {
    echo "usage: $0 {run <test-name>|start|stop}" >&2
}

use_launchctl() {
    [[ "$(uname -s)" == "Darwin" ]] && command -v launchctl >/dev/null 2>&1
}

build_programs() {
    cd "$root"
    cargo build-sbf --tools-version "$sbf_tools_version" \
        --manifest-path programs/shielded-pool/Cargo.toml \
        -- --features bpf-entrypoint
    cargo build-sbf --tools-version "$sbf_tools_version" \
        --manifest-path program-tests/zone-test-program/Cargo.toml
}

stop_pid() {
    if [[ ! -f "$pid_file" ]]; then
        return
    fi

    local pid
    pid=$(cat "$pid_file")
    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
        local cmd
        cmd=$(ps -p "$pid" -o command= 2>/dev/null || true)
        if [[ "$cmd" != *solana-test-validator* || "$cmd" != *"$ledger"* ]]; then
            echo "pid file points to an unmanaged process: $pid" >&2
            exit 1
        fi

        kill "$pid"
        for _ in $(seq 1 50); do
            if ! kill -0 "$pid" >/dev/null 2>&1; then
                break
            fi
            sleep 0.2
        done
        if kill -0 "$pid" >/dev/null 2>&1; then
            echo "validator pid $pid did not stop" >&2
            exit 1
        fi
        echo "stopped localnet validator pid $pid"
    fi
    rm -f "$pid_file"
}

stop_launchd() {
    use_launchctl || return

    local labels=("$launchd_label")
    if [[ -f "$label_file" ]]; then
        labels+=("$(cat "$label_file")")
    fi
    labels+=("com.zolana.localnet-proofless")

    local label
    for label in "${labels[@]}"; do
        if [[ -n "$label" ]] && launchctl remove "$label" >/dev/null 2>&1; then
            echo "stopped localnet validator label $label"
        fi
    done
    rm -f "$label_file"
}

stop_validator() {
    mkdir -p "$state_dir"
    stop_launchd
    stop_pid
}

start_validator() {
    local validator_bin
    validator_bin=$(command -v solana-test-validator)

    mkdir -p "$state_dir"
    stop_validator
    rm -rf "$ledger"
    : > "$log_file"

    local validator_args=(
        "$validator_bin"
        --quiet
        --reset
        --ledger "$ledger"
        --rpc-port "$rpc_port"
        --faucet-port "$faucet_port"
        --bpf-program "$shielded_pool_program_id" "$root/target/deploy/shielded_pool_program.so"
        --bpf-program "$zone_test_program_id" "$root/target/deploy/zone_test_program.so"
    )

    if use_launchctl; then
        launchctl submit -l "$launchd_label" -o "$log_file" -e "$log_file" -- "${validator_args[@]}"
        echo "$launchd_label" > "$label_file"
        rm -f "$pid_file"
    else
        nohup "${validator_args[@]}" > "$log_file" 2>&1 &
        echo "$!" > "$pid_file"
        rm -f "$label_file"
        disown || true
    fi

    wait_for_validator
}

wait_for_validator() {
    for _ in $(seq 1 60); do
        if [[ -f "$pid_file" ]]; then
            local pid
            pid=$(cat "$pid_file")
            if [[ -n "$pid" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
                cat "$log_file" >&2
                exit 1
            fi
        fi

        if solana --url "$rpc_url" cluster-version >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done

    cat "$log_file" >&2
    echo "localnet validator did not become ready at $rpc_url" >&2
    exit 1
}

print_status() {
    echo "localnet validator left running"
    echo "  rpc:    $rpc_url"
    echo "  ledger: $ledger"
    echo "  log:    $log_file"
    if [[ -f "$label_file" ]]; then
        echo "  label:  $(cat "$label_file")"
    elif [[ -f "$pid_file" ]]; then
        echo "  pid:    $(cat "$pid_file")"
    fi
}

run_test() {
    local test_name="${1:-}"
    if [[ -z "$test_name" ]]; then
        usage
        exit 2
    fi

    build_programs
    start_validator

    cd "$root"
    set +e
    ZOLANA_LOCALNET_URL="$rpc_url" cargo test \
        -p zolana-program-test \
        --features localnet \
        --test "$test_name" \
        -- --nocapture
    local status=$?
    set -e

    print_status
    exit "$status"
}

case "${1:-}" in
    run)
        shift
        run_test "$@"
        ;;
    start)
        build_programs
        start_validator
        print_status
        ;;
    stop)
        stop_validator
        ;;
    *)
        usage
        exit 2
        ;;
esac
