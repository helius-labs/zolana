# Simulator profiling and benchmark settings

The earlier localnet runs launched Surfpool with `--offline --no-tui --no-deploy --no-studio`. These flags leave instruction profiling enabled. The installed binary supports `--disable-instruction-profiling`; both benchmark harnesses now pass that exact flag when `E2E_BENCH_INSTRUCTION_PROFILING=0`. The benchmark runner defaults this setting to `0` and records it in the artifact manifest. Other harness users retain their existing behavior when the variable is absent.

The shared CLI already forwards `--validator-args=--disable-instruction-profiling` without translation. No CLI, SBF program, circuit or key change is required. The actual validator launch line provides a second record of the effective flag.

## Source evidence

The repository pins Surfpool release tag `v1.6.0-light`. The observed binary at `target/tools/surfpool` has SHA256 `41182ea7d4c7f0b293e3336730817ff04d388f4054ce59b2f4b153844d1e05b7`.

- [CLI flag and effective configuration](https://github.com/Lightprotocol/surfpool/blob/v1.6.0-light/crates/cli/src/cli/mod.rs#L554-L556): `disable_instruction_profiling` is false unless specified; the CLI assigns its inverse to `instruction_profiling_enabled` at line 751. `--no-studio` is independent.
- [Serial transaction loop](https://github.com/Lightprotocol/surfpool/blob/v1.6.0-light/crates/core/src/runloops/mod.rs#L571-L579): the runloop awaits each `ProcessTransaction` before processing another command.
- [RPC submission wait](https://github.com/Lightprotocol/surfpool/blob/v1.6.0-light/crates/core/src/rpc/full.rs#L1751-L1768): `sendTransaction` enqueues the transaction and waits for its processing result before replying.
- [Instruction-prefix replay](https://github.com/Lightprotocol/surfpool/blob/v1.6.0-light/crates/core/src/surfnet/locker.rs#L2014-L2121): profiling iterates over every instruction prefix, clones the SVM and executes the prefix. Actual transaction execution follows profiling. This adds simulator work that depends on how instructions are packed.

The native clients use `solana-rpc-client` 4.2.2 and Tokio 1.53.1. Tokio explicitly supports simultaneous `Runtime::block_on` calls from multiple threads on a current-thread runtime; sharing that runtime alone does not establish that HTTP requests run serially. Surfpool's serial processing and prefix replay are stronger source-supported explanations for the observed upload behavior, but source inspection does not quantify their contributions.

## Controlled comparison

Apply the same profiling setting to admission, occupied-H10 DAG admission and PR320. Preserve confirmation commitment, polling intervals, proving concurrency, resident-key policy, inclusion of every spend operation, and recipient decryption. Compare fresh results only after all endpoints and postconditions pass. Removing diagnostic simulator work is a measurement correction, not an architectural speedup; previous profiling-enabled timings must keep their original labels.

Both native benchmark targets compiled and completed matched 512-input runs. Profiling-disabled results, their limited sample size and the separately labeled profiling-enabled comparison are in [the assessment](../MERGE_EXPERIMENTS.md).
