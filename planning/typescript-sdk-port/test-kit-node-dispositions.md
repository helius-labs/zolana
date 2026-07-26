# `@zolana/test-kit/node` Rust-root disposition ledger

Rust authority: `sdk-libs/program-test/src/lib.rs` and its modules at the
current worktree tip. TypeScript authority: `@zolana/test-kit` root plus
`@zolana/test-kit/node`.

The frozen inventory already maps each `program-test` Rust file to a TypeScript
owner under `test-kit/src/`. This ledger answers the gate1-walk gap `TK-DISP`:
the `/node` annex star-exports those helpers without a named disposition against
the Rust crate root.

| Rust (`zolana_program_test`) | TypeScript disposition | Notes |
| --- | --- | --- |
| `ZolanaProgramTest` | **omit** | LiteSVM in-process harness. TypeScript drives a real localnet via `startLocalStack` instead. |
| `ProgramTestError` | **adapt** → `TestKitError` | String codes (`TEST_KIT_*`) rather than a Rust enum; root export. |
| `events::{deposit_output_from_event, index_events, indexed_events_from_meta, parsed_instruction_from_compiled, parsed_instruction_groups_from_meta, single_deposit_view, DepositOutput, IndexedEvent, InstructionGroup, ParsedInstruction}` | **adapt / partial** | `test-kit/src/events.ts` exposes plain shapes (`ParsedInstruction`, `InstructionGroup`, `IndexedOutput`, `IndexedTransaction`) and grouping helpers. No Borsh `GeneralEvent` decoder (see `E05`/`E06`). |
| `indexer::{shielded_transaction_from_general_event, IndexedPayload, IndexedUtxo, IndexerError, ProoflessOutput, TestIndexer}` | **adapt** → `TestIndexer` | In-memory test indexer; Photon JSON path stays in `@zolana/indexer-api`. |
| `instructions::{create_tree_instructions, rpc_state_root, system_create_account_ix, ZONE_TEST_PROGRAM_ID}` | **port** | `test-kit/src/instructions.ts`. |
| `rpc::IndexedTransaction` / `Rpc` re-export | **adapt** → `TestRpc` / shapes | Implements `@zolana/client` `Rpc` for harness use. |
| `admin` (private Rust mod) | **port** | `test-kit/src/admin.ts`; annex-only. |
| `paths` | **port** | `test-kit/src/paths.ts` (`WORKSPACE_ROOT`, `programBinaryPath`, …). |
| `proofless` | **port** | `test-kit/src/proofless.ts`. |
| `spl` | **port** | `test-kit/src/spl.ts`. |
| `wallet_data` | **port** | `test-kit/src/wallet-data.ts`. |
| `zone` | **port** | `test-kit/src/zone.ts`. |
| (no Rust module) `harness`, `prover`, `standard-accounts`, `user-registry` | **TypeScript-only annex** | E2E helpers with no crate-root counterpart; documented as test infrastructure. |
| Root five names in `public-exports.md` | **port / adapt** | `TestKitError`, `LocalStack`, `startLocalStack`, `fixtureBytes`, `createTestWallet` on `@zolana/test-kit` root. |

`@zolana/test-kit/node` re-exports the annex modules above plus
`localStackUrls`, `sidecarPorts`, `startLocalStack`, and `redactDiagnostic`.
Nothing on `/node` is SDK semver. Root `exports.test.ts` refuses annex names on
the default entry point.
