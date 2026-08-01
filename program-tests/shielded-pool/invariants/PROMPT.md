# Invariant Extraction Prompt: shielded-pool

You are a Senior Solana Security & Testing Engineer with deep experience auditing native/Pinocchio programs and ZK protocols (Groth16, nullifier trees, shielded pools).

Your only task is to extract from the source code a maximally complete, precise, and actionable list of invariants that must be covered by tests. Do not generate the tests themselves -- only the list of invariants.

### Analysis Scope

Analyze the following code (validation is spread between the program and the interface crate -- both are mandatory):

- `programs/shielded-pool/src/**` -- entrypoint (`lib.rs`), dispatch by `InstructionTag`, instruction processors, `loader.rs` modules (all `load_*` functions), `shared.rs`, `verifier.rs`, `hash.rs`, `event.rs`
- `program-libs/interface/src/error.rs` -- the `ShieldedPoolError` enum (codes 7000+)
- `program-libs/interface/src/state/**` -- state structs, `discriminator.rs`, the `from_account_info_checked` / `init` methods
- `program-libs/interface/src/instruction/**` -- instruction data structs, `zero_copy_at` parsing, tags
- `docs/spec.md` -- the source of truth for protocol semantics; use it only as a reference

### Hard Rules

1. Work ONLY with the provided source code. Do not invent anything.
2. If information is insufficient, write `INSUFFICIENT_INFO: <what is missing>`.
3. If the code diverges from spec.md, do not silently pick a side -- flag it as `SPEC_DIVERGENCE: <file/lines> vs <spec section>`.
4. Every invariant must be verifiable by a single test. Give the exact location: `path/file.rs:lines`, function name.
5. Prioritize security-critical (fund theft/freeze, double-spend, authority takeover) and state-critical invariants.

### Formulation Rules (mandatory for every invariant)

1. **One claim per invariant.** If the statement contains an "and" joining independent properties, split it into two invariants.
2. **Explicit quantifiers.** Always "every", "all", "no", "some". Never "any" without qualification.
3. **Explicit state snapshots.** Do not rely on verb tense: write "the balance after a successful execution is exactly the balance before minus `amount`".
4. **Exact comparison vocabulary**, consistent across the whole list: "exactly" (=), "increases by exactly" (after = before + x), "at least" (>=), "never exceeds" (<=), "strictly greater than" (>), "is unchanged" (after = before). Banned words: "updated", "correctly", "properly".
5. **Success + failure for every operation.** At least two invariants per instruction: a success postcondition and a rollback property for failure ("when the instruction returns Err, no account is modified").
6. **Frame conditions.** After describing what the operation changes, describe what it must NOT change ("every account other than X and Y is unchanged").
7. **Authorization separate from correctness.** "Only signer Z can invoke" and "on success field F becomes exactly V" are two different invariants.
8. **Do not restate the implementation.** "The function subtracts amount from the sender" is code, not an invariant. An invariant states what must hold regardless of the implementation.

### Classification: assign a Kind to every invariant

- `state` -- true at every observable moment
- `precondition` -- must be true for the operation to succeed
- `postcondition` -- true after a successful completion
- `frame` -- what the operation does not change
- `rollback` -- true when the operation returns Err (atomicity)
- `reachability` -- what must always remain possible (e.g. the forester can always update the nullifier tree; the owner can always withdraw funds)

### Invariant Categories (domains)

1. **Account Constraints** -- `is_signer()`, writable, `owned_by()`, discriminator (first byte), `data_len` exactly `SIZE`, canonical bump via `find_program_address` on PDA creation (verify_pda), system_program checks, rent-exemption. Remember the project rules: for already-initialized accounts, discriminator + ownership is sufficient (derivation is not checked unless access control depends on it); every account access goes through a `load_*` function in a loader.rs.
2. **Instruction Data Validation** -- minimum/exact payload length, `InstructionTag::try_from` rejects unknown tags, value ranges, zero-copy parsing (`zero_copy_at`) on truncated/extended data, required fields, trailing bytes.
3. **State Invariants** -- allowed values of state struct fields (`ProtocolConfig`, `Tree`, `ZoneConfig`, `SplAssetCounter`, `SplAssetRegistry`); monotonicity (tree indices, counters only grow); `init` requires `data[0] == 0` (re-initialization is impossible); account size matches `SIZE` exactly.
4. **Authorization & Access Control** -- who may invoke each instruction (protocol authority, zone owner, forester, depositor); changing an owner/authority requires the current one's signature; signer checks live in the processor, not nested deeper.
5. **ZK / Proof & Tree Invariants** (a mandatory separate category for this program):
   - proof verification: eddsa rail (standard Groth16, no commitment) vs P256 rail (BSB22, `vk_commitment_g2: Some`); rail mismatch -> `MismatchedTransactProofRail`
   - shape validity (`nInputs x nOutputs`) -> `InvalidTransactShape`, `InvalidMergeShape`
   - public input hash construction: every public input enters the hash exactly once; tampering with any input invalidates the proof
   - root freshness: a stale nullifier root -> `StaleNullifierRoot`
   - double-spend: every nullifier can be inserted at most once; a repeated spend -> Err
   - `TreePaused` blocks operations on the tree; `ExpiredTransaction` after expiry
   - state tree append: the index increases by exactly the number of output notes
6. **Value & Arithmetic Safety** -- checked math on all amounts/indices; overflow/underflow; `BothPublicAmountsSet`; min/max amounts; balance conservation: sum of inputs = sum of outputs + public amounts + fees (state the exact formula from the code).
7. **Cross-Instruction / Lifecycle** -- ordering: create -> use -> close; `EmitEvent` is a no-op when invoked directly (invariant: it modifies no account); trees are created before transactions; merge is disabled via `MergeDisabled`; `ZoneAuthorityTransactDisabled`.
8. **Error Conditions** -- for EVERY `ShieldedPoolError` variant (7000, 7001, ... -- enumerate all of them from error.rs) at least one invariant of the form "condition C results in exactly error E". Separately: error codes are stable (pinned in `error_codes_are_stable`).
9. **CPI & External Calls** -- the target program of every CPI, signer seeds in `invoke_signed`, SPL transfers (mint/decimals/authority of interface accounts).
10. **Resource & Economic Invariants** -- lamports do not leak: the sum of lamports across all transaction accounts is conserved (minus rent for new accounts); a fee payer exists ONLY on instructions that transfer lamports; every close instruction has a dedicated rent_recipient; an attacker who donates lamports to a PDA before creation (cold path) cannot block the creation.

### Completeness Requirement: coverage matrix

The program dispatches 18 tags: EmitEvent, Transact, ZoneTransact, ZoneAuthorityTransact, CreateTree, BatchUpdateNullifierTree, Deposit, ZoneDeposit, CreateAssetCounter, CreateSplInterface, CreateProtocolConfig, UpdateProtocolConfig, PauseTree, CreateZoneConfig, UpdateZoneConfigOwner, UpdateZoneConfig, MergeTransact, ZoneMergeTransact.

Provide in `README.md` a matrix: instruction x (account constraints / data validation / authz / success postcondition / rollback / frame). An empty cell = a gap in the list -- either add an invariant or flag it as `INSUFFICIENT_INFO`.

### Output Format (strict)

Do NOT answer inline. Write the results as md files into `program-tests/shielded-pool/invariants/`, one file per instruction group (mirroring the test tree), plus cross-cutting and the index:

| File | Covers |
|---|---|
| `transact.md` | Transact, ZoneTransact, ZoneAuthorityTransact |
| `deposit.md` | Deposit, ZoneDeposit |
| `merge.md` | MergeTransact, ZoneMergeTransact |
| `tree.md` | CreateTree, BatchUpdateNullifierTree, PauseTree |
| `protocol-config.md` | CreateProtocolConfig, UpdateProtocolConfig |
| `zone-config.md` | CreateZoneConfig, UpdateZoneConfig, UpdateZoneConfigOwner |
| `spl.md` | CreateAssetCounter, CreateSplInterface |
| `event.md` | EmitEvent |
| `cross-cutting.md` | invariants spanning multiple instructions: balance conservation formula, lamports conservation, error-code stability, ZK/proof-rail invariants, shared state-struct invariants |
| `README.md` | coverage matrix + summary (format below) |

An invariant that applies to more than one instruction goes ONLY into `cross-cutting.md` (listing the affected instructions), never duplicated per file.

Each instruction file uses this structure:

```markdown
# <Instruction group> Invariants

## <InstructionTag>

### <Category name>
- [ ] **INV-<TAG>-<NN>: <short name>**
  - Kind: state | precondition | postcondition | frame | rollback | reachability
  - Statement: <one precise claim with explicit quantifiers and snapshots>
  - Location: `programs/shielded-pool/src/instructions/<...>.rs:<lines>` (`fn <name>`)
  - Error: `ShieldedPoolError::<Variant> = <code>` (if applicable)
  - Severity: Critical (funds/double-spend) | High | Medium
  - Suggested test: negative | positive | property (proptest) | fuzz; harness: mollusk unit / litesvm / program-tests integration (`cargo test-sbf`)
```

`<TAG>` is a short instruction slug (e.g. `TRANSACT`, `ZONE-DEPOSIT`); cross-cutting invariants use `INV-XC-<NN>`. IDs are stable once assigned -- never renumber.

When a test covering an invariant lands, tick its checkbox and append a `Covered by:` line with the test path and test name.

`README.md` structure:

```markdown
# Shielded Pool Invariants

Test-coverage checklist derived from the program source. Detailed invariants
live in the per-instruction files; `docs/spec.md` remains the protocol source
of truth.

## Coverage Matrix
| Instruction | File | Accounts | Data | Authz | Success | Rollback | Frame |
|---|---|---|---|---|---|---|---|
...

## Summary
- Total invariants: X
- Critical (funds/double-spend): Y
- High: Z
- SPEC_DIVERGENCE items: ...
- INSUFFICIENT_INFO items: ...
```

Matrix cells contain the invariant IDs covering that cell (e.g. `INV-TRANSACT-01`), not check marks.

### Anti-Patterns (do not include in the list)

- Invariants that only exercise derived serialization (borsh/wincode round-trip) -- they test the derive macro, not the program.
- Invariants duplicating SVM runtime guarantees (e.g. "an account owned by another program cannot be written to"), unless the code relies on them in a non-obvious way.
- Generic statements without specifics ("the authority must be correct").

Now start the analysis with `programs/shielded-pool/src/lib.rs` (entrypoint and dispatch), then walk the instructions in tag order.
