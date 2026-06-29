# Plan: cpi-test creates a program-owned account with a persistent address

Date: 2026-06-29

## IMPORTANT (user instructions / requirements)
- User: "fix the test in program-tests/cpi-test-program to create the account with address."
- Scope chosen by user: **Full program-owned account** (a genuine program-owned UTXO
  carrying a derived persistent `address`), not a minimal compile-fix.
- Discovery is by the **address tag**: a program-owned output puts its `address` in the
  ciphertext owner-tag field that Photon already indexes (spec line 973). Query Photon
  with the address as the tag. (User corrected an earlier wrong "Photon can't discover"
  assumption.)
- Split into todos, work through one by one, test as we go. Use a subagent to research
  if stuck. No batching. No emojis. No code comments that only narrate.

## Goal
The CPI fixture creates a new program-owned account: a `transact` with
1. an **address-creation input slot** (`address_slot: true`, owner = CPI program) that
   derives `address = utxo::address(tree_pubkey, program_data_hash)`, proves it absent
   against the nullifier(=address) tree, and inserts it; and
2. a **program-owned output** (`program_owner: Some(CPI)`, non-zero program data,
   `address` set via `with_address`) whose ciphertext owner tag = `address`.
Then assert the account exists: Photon indexes the tx under the address tag, the on-chain
`output_utxo_hash` equals the recomputed program-owned leaf, and the address is now in the
address tree.

## Strategy: hybrid (reuse builder encryption + low-level prover for the address slot)
The high-level `assemble`/`into_prover` discards program ownership and address slots; the
builder's encryption pipeline (`finalize`) is the only sane source of ciphertexts/output
contexts. So:
- Use the builder to produce the SignedTransaction (program-owned output with
  `owner_address` retained for encryption, `with_address(tree)`, program data) -> reuse
  its ciphertexts + `external_data` + output hashes.
- Build the prover inputs at the low level in the test: real payer spend + the
  address-creation `TransferSpendInput`, call `TransferProver::build()`, then construct the
  `TransactIxData` from the SignedTransaction's outputs/ciphertexts + the low-level inputs.

## Tasks
1. Wire `OutputUtxo::ciphertext_owner_tag()` into the builder so a program-owned output's
   ciphertext/event view_tag = its `address` (shared change, guarded so user-owned outputs
   are byte-for-byte unchanged). Removes the dead method.
2. Add a low-level assemble path the test can call to inject an address-creation slot and a
   program-owned input/output, returning `(TransactIxData-without-proof, prover_inputs)`.
   Prefer reusing client internals; make the minimal items `pub(crate)`/`pub` as needed.
3. Rewrite `steps/program_governed_transact.rs`: build the program-owned output
   (`program_owner`, `with_address`, program data), add the address-creation slot, fetch
   the address non-inclusion proof, prove (eddsa rail), submit via the CPI fixture.
4. Update `world.rs::build_expected` (and the expected model) to compute the program-owned
   leaf: owner = `pk_field(CPI)`, `address` derived, `program_data_hash` set. Assert via
   address-tag discovery + on-chain leaf match + address-in-tree.
5. Update the `.feature` wording and any `deposit_action.rs`/`world.rs` field-rename
   fallout (e.g. the `address: program_id.map(..)` hack -> real derived address).
6. Compile (`cargo check`/`clippy`), fix all lints, then run the localnet+Photon scenario.

## Acceptance criteria
- Scenario creates a program-owned account; Photon returns the tx queried by the address
  tag; the on-chain `output_utxo_hash` equals the recomputed program-owned leaf; the
  derived address is present in the address tree post-submit.
- The forged-cpi-signer negative scenario still rejects with `UnauthorizedCaller`.
- No dead code, no clippy/gofmt regressions; other transact tests unaffected (shared
  builder change is guarded to the program-owned branch).
