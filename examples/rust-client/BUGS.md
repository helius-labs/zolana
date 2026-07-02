# Bug log

Issues hit while building and running the rust client examples, each with its
fix. Entries flagged **[SDK]** / **[CLI]** / **[prover]** / **[indexer]** point at
the underlying crates a real client developer would also hit; **[example]** are
mistakes in this crate's own code, kept for completeness.

## 1. [example] `register` helper shadowed the `register` instruction builder

- **Symptom:** `error[E0255]: register redefined here` + `E0061: this function takes 2 arguments but 3 were supplied`. The local `pub fn register` collided with the imported `zolana_user_registry_interface::instruction::register`.
- **Root cause:** name clash between the harness helper and the instruction builder it calls.
- **Fix:** import the builder as `register as register_ix` and call `register_ix(..)` inside the helper.

## 2. [env] Photon binary and prover keys gated behind GitHub SAML

- **Symptom:** `tools/install-photon.sh` (and `just ensure-photon` once it falls through to it) fails with `HTTP 403: Resource protected by organization SAML enforcement` when fetching the `photon-zolana-*` release asset. The same gate blocks the prover's `gh release download` of the proving keys on first prove.
- **Root cause:** environment / access, not code. The Photon release assets and the transfer/merge proving keys live on a SAML-enforced private org; authorizing the token is a browser SSO flow.
- **Fix — Photon:** build Photon locally against the current zolana checkout instead of downloading it (`just build-photon` -> `target/bin/photon`). This also guarantees Photon parses the exact on-chain event layout the deployed program emits.
- **Fix — proving keys:** the committed verifying keys correspond to the *published* proving keys. The proof-path examples use the published keys, which requires authorizing `gh` for the org once (browser SSO); the prover then auto-downloads them on first prove and verifies them against the release `CHECKSUM`.
- **Impact on the examples:** every example reads from the indexer, so all need Photon. The proof-path examples (transfer / withdraw) additionally need the published proving keys. The proofless examples (`action_spl_deposit`, `*_sync_balance`) need Photon but not the prover keys.

## 3. [example] Deposit examples raced the indexer

- **Symptom:** a deposit example intermittently printed `balances=[]` (empty) on exit 0; a re-run printed the correct balance.
- **Root cause:** the deposit examples called `sync_wallet` immediately after the send returned. A transaction confirming on-chain does not mean Photon has indexed it; `sync_wallet` then queried the indexer before the deposit's encrypted output was indexed and read an empty balance.
- **Where it lives:** the example files. It is a real client-facing papercut: the deposit action returns a confirmed signature with no built-in indexing barrier. `Submit::execute` has the same shape — it returns on confirmation and does not wait for the indexer.
- **Fix:** wait on `wait_for_indexed_transaction(&indexer, view_tag, signature)` before `sync_wallet` in each deposit example (and inside `submit_private_transaction` after `Submit::execute`).

## 4. [example] Fee payer is a proof-bound value

- **Symptom:** an instruction-tier transfer/withdraw failed on-chain with `custom program error: 0x1b60` = 7008 = `TransactProofVerificationFailed`, while the matching `action_*` example passed.
- **Root cause:** `ClientTransaction::new` hashes the fee payer into `payer_pubkey_hash`, a public input bound into the transfer proof. Building the transaction with one payer and submitting the `Transact` with another makes the on-chain verifier recompute against the wrong key, so verification fails.
- **Fix:** the harness's `client_transaction` seeds the fee payer from `context.payer`, and `submit_private_transaction` submits with the same `context.payer`, so the proof binds the same key the instruction submits. `Submit::execute` takes the payer directly, so the two can no longer drift within the harness.

## Migration notes (revised for the SDK devx branch)

Changes absorbed when moving this crate from the earlier SDK to
`feat/sdk-devx-improvements`:

- **`AssetRegistry` moved onto `Wallet`.** `Wallet::new(keypair, registry)` now
  takes the registry at construction, and `sync_wallet`,
  `get_private_token_balances`, `create_transfer_sync`, and
  `create_withdrawal_sync` no longer take a separate registry argument. The raw
  path passes `wallet.registry` to `Transaction::sign`.
- **One-call submit.** `submit_private_transaction` is now a thin wrapper over
  the `Submit` action, which fetches the input proofs, assembles, proves, and
  sends in one call. The hand-rolled per-input `wait_for_merkle_proof` /
  `wait_for_non_inclusion_proof` loop is gone.
- **Idempotent ATA action.** `ensure_associated_token_account` wraps the
  `create_associated_token_account` client action instead of hand-building the
  instruction and doing a prior existence check.
- **`CreateDeposit.memo`.** Deposits take an optional in-the-clear memo
  (`memo: None` here).
- **Per-user merge authority.** `CreateProtocolConfig` dropped its
  `merge_authority` field; merge authority now lives on the registry record.
- **`Transact.cpi_signer` removed.** The `Transact` builder no longer carries a
  `cpi_signer` field.
