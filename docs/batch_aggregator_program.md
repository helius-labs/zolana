# Batch Aggregator Program

The Batch Aggregator is a confidential DeFi program built on the Solana Privacy Program
(SPP). It batches many users' confidential swaps in one direction into one public DeFi trade:
users deposit `asset_in` (e.g. SOL) into a withdrawal batch, an operator drains the batch,
swaps it for `asset_out` (e.g. USDC) on public DeFi, and settles the proceeds back to
depositors through a deposit batch. Amounts stay private; the assets, the depositor pubkeys,
and the aggregate volume are public. The reverse direction is a separate pair.

It does not configure an SPP zone. It owns SPP [batch accounts](spec.md#batch-accounts) and
drives them by CPI, using one program-wide `authority` PDA as the SPP `owner` of every batch.

## User Flow

```mermaid
sequenceDiagram
    participant Operator
    participant User
    participant Agg as Aggregator
    participant SPP as SPP
    participant DeFi as Public DeFi

    Note over Operator,Agg: Operator creates batch accounts per asset (create_pair)

    Note over User: 1. Users deposit into batches
    User->>Agg: deposit (confidential transfer)
    Agg->>SPP: CPI transact insert
    Note over SPP: invalidate input UTXO <br> append UTXO hash to batch account <br> user pubkey public, amount private, asset public

    Note over Operator: 2. Execute batch (full or window closed)
    Operator->>Agg: lock, execute_withdrawal
    Agg->>SPP: CPI execute_batch_withdrawal <br> 1 ZKP for one or many withdrawal batches
    SPP-->>Agg: SPL transfer to swap account
    Operator->>Agg: swap
    Agg->>DeFi: perform swap(s)
    DeFi-->>Agg: swapped tokens
    Note over Agg: write PairConfig <br> swapped amounts + settlement hash chain

    Note over Operator: 3. Set up batch deposit accounts for settlement
    Operator->>Agg: open_settlement
    Note over Agg,SPP: ZKP proves settlement UTXO hash chains valid (from PairConfig) <br> set_batch_hash_chain in deposit account(s)

    Note over Operator: 4. Settle with batch deposit concurrently
    Operator->>Agg: settle (chunks, concurrent)
    Agg->>SPP: CPI execute_batch_deposit
    SPP-->>SPP: append settlement UTXOs to tree
```

## Table of Contents

- [Glossary](#glossary)
- [Accounts](#accounts)
  - [Authority](#authority)
  - [AggregatorConfig](#aggregatorconfig)
  - [OperatorConfig](#operatorconfig)
  - [PairConfig](#pairconfig)
- [Instructions](#instructions)
  - Admin
    - [initialize](#initialize)
    - [update_config](#update_config)
    - [create_operator](#create_operator)
    - [close_operator](#close_operator)
  - Pair lifecycle
    - [create_pair](#create_pair)
    - [close_pair](#close_pair)
  - Deposit
    - [deposit](#deposit)
  - Execute
    - [lock](#lock)
    - [execute_withdrawal](#execute_withdrawal)
    - [swap](#swap)
  - Settle
    - [open_settlement](#open_settlement)
    - [settle](#settle)

## Glossary

Types used in this document. Shared SPP types are defined in [spec.md](spec.md#glossary).

| Type | Encoding | Definition |
| --- | --- | --- |
| `Address` | `[u8; 32]` | Solana account address. |
| `asset_id` | `u64` | Asset identifier in UTXOs; `1` is SOL, each SPL mint `≥ 2`. See [spec.md](spec.md#glossary). |
| `SppProof` | `[u8; 192]` | Compressed Groth16 SPP proof with commitment; verified in SPP. |
| `TransactIxData` | — | SPP `transact` instruction data. See [spec.md](spec.md#transact). |
| `ExecuteBatchDepositIxData` | — | SPP `execute_batch_deposit` chunk. See [spec.md](spec.md#execute_batch_deposit). |

## Accounts

Layouts of accounts owned by the batch aggregator program, and which instructions create,
write, and close them.

### Authority

Program-wide signer PDA, seeds `[b"authority"]`. It is the SPP `owner` of every batch
account and the owner of the program's token accounts, and signs every SPP CPI and DeFi swap.
Holds no data. Because all batches share this owner, SPP enforces no isolation between
operators or pairs; the program checks each batch belongs to the calling `PairConfig` itself.

### AggregatorConfig

One per program. Holds the protocol authority and the asset allow-list. Operators can only be
created by the protocol authority.

Derivation seed: `[b"config"]`.

Created by `initialize`. `update_config` rotates `authority` or edits the allow-list; setting
`authority` to the default freezes it.

```rust
struct AggregatorConfig {
    /// Account type tag.
    discriminator: u8,
    /// Creates operators and updates this config. The default value freezes it.
    authority: Address,
    /// Protocol fee in basis points; upper-bounds each `PairConfig.fee_bps`.
    max_fee_bps: u16,
    /// Assets the aggregator supports.
    assets: Vec<asset_id>,
}
```

### OperatorConfig

One per operator, created only by the protocol authority. Names the key that signs the
operator's pair and round instructions.

Derivation seed: `[b"operator", id]`.

Created by `create_operator`. `close_operator` reclaims rent.

```rust
struct OperatorConfig {
    /// Account type tag.
    discriminator: u8,
    /// Operator id; PDA seed.
    id: u64,
    /// Signs this operator's create_pair / lock / execute / swap / settle calls.
    authority: Address,
}
```

### PairConfig

A one-directional market `asset_in -> asset_out` under one operator: the single aggregator
account per pair. It holds the swap parameters, the two SPP batch accounts it drives, and the
current round's swap data. Multiple pairs of the same assets are allowed (e.g. both swap
directions, or different windows), disambiguated by `id`.

Derivation seed: `[b"pair", operator, id]`.

Created by `create_pair`, which also creates the SPP withdrawal and deposit batches (owned by
`authority`). `lock`, `execute_withdrawal`, and `swap` advance `state` and fill the round's
swap fields; `open_settlement` and `settle` consume them; the final `settle` resets the round
fields and the batches for the next round; `close_pair` closes everything and reclaims rent.

```rust
struct PairConfig {
    /// Account type tag.
    discriminator: u8,
    /// OperatorConfig this pair belongs to.
    operator: Address,
    /// Disambiguates pairs; PDA seed.
    id: u64,
    /// Deposited asset (swap input).
    asset_in: asset_id,
    /// Settled asset (swap output).
    asset_out: asset_id,
    /// Swap fee in basis points; <= AggregatorConfig.max_fee_bps.
    fee_bps: u16,
    /// SPP batch_size for the withdrawal and deposit batches.
    batch_size: u16,
    /// Deposits accepted until lock, or until created_at + window.
    window: i64,
    /// Round counter; advanced by the final settle chunk.
    round: u64,
    /// SPP batch accounts owned by `authority`, reused each round.
    withdrawal: Address,
    deposit: Address,
    /// Current round's swap data, filled across execute_withdrawal -> swap ->
    /// open_settlement and zeroed by the final settle chunk.
    withdrawal_chain: [u8; 32],
    amount_in: u64,
    amount_out: u64,
    settlement_chain: [u8; 32],
    /// Collecting | Locked | Withdrawn | Swapped | Settling.
    state: u8,
}
```

## Instructions

**Admin**

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | [initialize](#initialize) | 0 | Create the `AggregatorConfig`. | — | AggregatorConfig (create) | Protocol authority signs the value it writes |
| 2 | [update_config](#update_config) | 1 | Rotate `authority` or edit the allow-list; default `authority` freezes it. | — | AggregatorConfig | `authority` signs |
| 3 | [create_operator](#create_operator) | 2 | Create an `OperatorConfig`. | AggregatorConfig | OperatorConfig (create) | Protocol `authority` signs |
| 4 | [close_operator](#close_operator) | 3 | Close an operator and reclaim rent. | AggregatorConfig | OperatorConfig (close) | Protocol `authority` signs |

**Swap Pair**

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 5 | [create_pair](#create_pair) | 4 | Open a `PairConfig` and its SPP withdrawal and deposit batches (owned by `authority`). | OperatorConfig | PairConfig (create), BatchWithdrawal (CPI create), BatchDeposit (CPI create) | Operator `authority` signs |
| 6 | [close_pair](#close_pair) | 5 | Close an idle pair: its `PairConfig` and both batches; reclaim rent. | OperatorConfig | PairConfig (close), BatchWithdrawal (CPI close), BatchDeposit (CPI close) | Operator `authority` signs |

**Deposit**

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 7 | [deposit](#deposit) | 6 | Confidential transfer into a pair's withdrawal batch (CPIs SPP `transact`, `authority` co-signs the insert). | PairConfig | BatchWithdrawal (CPI), SPP trees (CPI), SPL interface | Depositor signs |

**Execute**

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 8 | [lock](#lock) | 7 | Close the deposit window; CPIs SPP `lock_batch_withdrawal_account`. | OperatorConfig | PairConfig, BatchWithdrawal (CPI) | Operator `authority` signs |
| 9 | [execute_withdrawal](#execute_withdrawal) | 8 | Drain the withdrawal batch to the `authority` token account; CPIs SPP `execute_batch_withdrawal`. | OperatorConfig | PairConfig, BatchWithdrawal (CPI), vault_in | Operator `authority` signs |
| 10 | [swap](#swap) | 9 | Swap on public DeFi and write the round into the `PairConfig`. | OperatorConfig | PairConfig, vault_in, vault_out | Operator `authority` signs |

**Settle**

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 11 | [open_settlement](#open_settlement) | 10 | Escrow `amount_out` into the pair's deposit batch and `set_batch_hash_chain` from the `PairConfig`. | OperatorConfig | PairConfig, BatchDeposit (CPI), vault_out | Operator `authority` signs |
| 12 | [settle](#settle) | 11 | Append a settlement chunk; CPIs SPP `execute_batch_deposit`. The final chunk resets the deposit batch and the `PairConfig` for the next round (not closed). | OperatorConfig | PairConfig, BatchDeposit (CPI), SPP tree (CPI) | Operator `authority` signs |

---

### initialize

Creates the program's single [`AggregatorConfig`](#aggregatorconfig) at its derived PDA.

**Accounts**

1. `payer` — pays rent; signer, writable.
2. `config` — created at its derived PDA; writable.
3. `system_program` — read.

**Instruction data**

```rust
struct InitializeIxData {
    authority: Address,
    max_fee_bps: u16,
    assets: Vec<asset_id>,
}
```

---

### update_config

Overwrites the [`AggregatorConfig`](#aggregatorconfig) mutable fields. Setting `authority`
to the default freezes the config.

**Accounts**

1. `authority` — must equal `config.authority`; signer.
2. `config` — updated; writable.

**Instruction data**

```rust
struct UpdateConfigIxData {
    authority: Address,
    max_fee_bps: u16,
    assets: Vec<asset_id>,
}
```

---

### create_operator

Creates an [`OperatorConfig`](#operatorconfig). Only the protocol authority may call it.

**Accounts**

1. `authority` — must equal `config.authority`; signer, writable (pays rent).
2. `config` — read.
3. `operator` — created at `[b"operator", id]`; writable.
4. `system_program` — read.

**Instruction data**

```rust
struct CreateOperatorIxData {
    id: u64,
    /// Signs the operator's pair and round instructions.
    operator_authority: Address,
}
```

---

### close_operator

Closes an [`OperatorConfig`](#operatorconfig) with no open pairs and reclaims rent. Takes no
instruction data.

**Accounts**

1. `authority` — must equal `config.authority`; signer.
2. `config` — read.
3. `operator` — closed; writable.
4. `rent_recipient` — receives the reclaimed rent; writable.

---

### create_pair

Creates a [`PairConfig`](#pairconfig) and the two SPP batch accounts it drives — a
[`BatchWithdrawalAccount`](spec.md#batch-accounts) for `asset_in` and a
[`BatchDepositAccount`](spec.md#batch-accounts) for `asset_out`, both owned by `authority`
(CPIing SPP `create_batch_withdrawal_account` and `create_batch_deposit_account`). Records the
two batch addresses in the config and sets `state = Collecting`. The deposit batch is created
empty; `open_settlement` escrows into it each round.

**Accounts**

1. `operator_authority` — must equal `operator.authority`; signer, writable (pays rent).
2. `operator` — read.
3. `pair_config` — created at `[b"pair", operator, id]`; writable.
4. `authority` — program PDA; the SPP `owner` of both batches; signs the SPP CPIs.
5. `withdrawal` — the SPP withdrawal batch, created by CPI; writable.
6. `deposit` — the SPP deposit batch, created by CPI; writable.
7. `spp_program` — SPP program (CPI target).
8. `system_program` — read.

**Instruction data**

```rust
struct CreatePairIxData {
    id: u64,
    asset_in: asset_id,
    asset_out: asset_id,
    fee_bps: u16,
    batch_size: u16,
    window: i64,
}
```

---

### close_pair

Closes a [`PairConfig`](#pairconfig) and its two SPP batch accounts, reclaiming rent. Callable
only when the pair is idle (the last round settled); an idle pair is not closed automatically,
the operator calls this explicitly. Takes no instruction data.

**Accounts**

1. `operator_authority` — must equal `operator.authority`; signer.
2. `operator` — read.
3. `pair_config` — closed; writable.
4. `authority` — program PDA; signs the SPP CPIs.
5. `withdrawal` — closed by CPI; writable.
6. `deposit` — closed by CPI; writable.
7. `spp_program` — SPP program (CPI target).
8. `rent_recipient` — receives the reclaimed rent; writable.

---

### deposit

A user joins a round: a confidential transfer that spends the depositor's `asset_in` UTXO and
routes the output into the pair's withdrawal batch. CPIs SPP [`transact`](spec.md#transact)
with `batch_inserts` set; `authority` co-signs the insert as the batch `owner`. The
depositor's settlement pubkey is public (the operator pays the swapped proceeds back to it);
the amount is private; the asset is public. Rejected once the deposit window has closed
(`state != Collecting` or past `window`).

**Accounts**

1. `depositor` — spends the input UTXO; signer, writable (fee payer).
2. `pair_config` — read.
3. `authority` — program PDA; co-signs the SPP insert.
4. `withdrawal` — the pair's withdrawal batch; writable.
5. `spp_program` — SPP program (CPI target).
6. `tree_accounts` — SPP Tree accounts the transfer touches; writable.
7. `spl_interface` — SPL interface account for `asset_in`; writable.

**Instruction data**

```rust
struct DepositIxData {
    /// SPP transact payload (proof, inputs, output hashes, ciphertexts, batch_inserts
    /// routing the output into the pair's withdrawal batch). See spec.md transact.
    transact: TransactIxData,
    /// Public pubkey the swapped proceeds settle to.
    settlement_pubkey: Address,
}
```

---

### lock

Closes the deposit window for a [`PairConfig`](#pairconfig): CPIs SPP `lock_batch_withdrawal_account` and
sets `state = Locked`. Callable once the window has elapsed or at the operator's discretion.

**Accounts**

1. `operator_authority` — must equal `operator.authority`; signer.
2. `operator` — read.
3. `pair_config` — `state` updated; writable.
4. `authority` — program PDA; signs the SPP CPI.
5. `withdrawal` — locked by CPI; writable.
6. `spp_program` — SPP program (CPI target).

---

### execute_withdrawal

Drains the withdrawal batch to the program's `asset_in` token account, CPIing SPP
`execute_batch_withdrawal`. Writes the drained `withdrawal_chain` and `amount_in` into the
[`PairConfig`](#pairconfig) for `swap`, and sets `state = Withdrawn`.

**Accounts**

1. `operator_authority` — must equal `operator.authority`; signer, writable (fee payer).
2. `operator` — read.
3. `pair_config` — `state`, `withdrawal_chain`, and `amount_in` written; writable.
4. `authority` — program PDA; SPP `owner`, signs the SPP CPI and receives the payout.
5. `withdrawal` — drained by CPI; writable.
6. `vault_in` — the program's `asset_in` token account (`authority`-owned) receiving the payout; writable.
7. `spp_program` — SPP program (CPI target).

**Instruction data**

```rust
struct ExecuteWithdrawalIxData {
    /// See spec.md execute_batch_withdrawal.
    proof: SppProof,
    aggregate_in: u64,
}
```

---

### swap

Swaps the drained `asset_in` for `asset_out` against public DeFi (CPI to the AMM, signed by
`authority`) and writes `amount_out` into the [`PairConfig`](#pairconfig) (`amount_in`
and `withdrawal_chain` were written by `execute_withdrawal`). Sets `state = Swapped`.

**Accounts**

1. `operator_authority` — must equal `operator.authority`; signer, writable (fee payer).
2. `operator` — read.
3. `pair_config` — `state` and `amount_out` written; writable.
4. `authority` — program PDA; signs the DeFi swap.
5. `vault_in`, `vault_out` — the program's token accounts; writable.
6. `amm_program`, `amm_accounts` — the DeFi venue (CPI target and its accounts).

**Instruction data**

```rust
struct SwapIxData {
    /// Minimum acceptable asset_out (slippage bound).
    min_out: u64,
}
```

The program writes `amount_out` into the [`PairConfig`](#pairconfig) from the CPI result.

---

### open_settlement

Escrows `amount_out` of `asset_out` into the pair's SPP
[`BatchDepositAccount`](spec.md#batch-accounts) and commits its settlement hash chain (CPIing
SPP `set_batch_hash_chain`). The deposit batch was created empty by `create_pair`; this funds
and chains it for the round. The settlement chain is recorded into the
[`PairConfig`](#pairconfig); the operator proves it distributes exactly `amount_out` to the
round's depositors. Sets `state = Settling`.

**Accounts**

1. `operator_authority` — must equal `operator.authority`; signer, writable (fee payer).
2. `operator` — read.
3. `pair_config` — `state` and settlement chain written; writable.
4. `authority` — program PDA; SPP `owner`, escrow source, signs the SPP CPIs.
5. `deposit` — the pair's SPP deposit batch; escrowed and chained by CPI; writable.
6. `vault_out` — escrow source token account; writable.
7. `spp_program` — SPP program (CPI target).

**Instruction data**

```rust
struct OpenSettlementIxData {
    settlement_chain: [u8; 32],
    num_inserts: u16,
}
```

---

### settle

Appends one chunk of the settlement chain to the SPP UTXO tree, CPIing SPP
`execute_batch_deposit`. Repeated until the chain is fully appended. The final chunk wipes the
SPP deposit batch and the pair's [`PairConfig`](#pairconfig) for the next round — both are
reset (chains and amounts zeroed, `PairConfig.round` advanced), not closed — so no separate
close instruction is needed. The deposit batch and `PairConfig` are closed only by `close_pair`.

**Accounts**

1. `operator_authority` — must equal `operator.authority`; signer, writable (fee payer).
2. `operator` — read.
3. `pair_config` — appended round read, then reset on the final chunk; writable.
4. `authority` — program PDA; SPP `owner`, signs the SPP CPI.
5. `deposit` — the SPP deposit batch; appended to, then reset on the final chunk; writable.
6. `spp_program` — SPP program (CPI target).
7. `tree_account` — SPP UTXO tree; writable.

**Instruction data**

```rust
struct SettleIxData {
    /// SPP execute_batch_deposit chunk; see spec.md.
    execute: ExecuteBatchDepositIxData,
}
```
