# Dynamic Swap

- Price updates are cheap: `update_price` touches only the pair account, and `create_escrow` prices the order at creation by reading that price.
- Unidirectional trading pairs (e.g. SOL -> USDC), each with its own authority (the maker) who sets the price.
- Committed liquidity: the pool is every UTXO owned by the pair's `pool_authority` PDA (destination asset). Each pool note's confidential data contains `booked`: the portion of its amount that the public accounting already counts. The pair account tracks a public `available_liquidity` and `open_reservations`. Invariants: per note `0 <= booked <= amount`, and globally `sum(booked) >= available_liquidity + open_reservations * max_order_size`. Each open escrow holds a `max_order_size` reservation, covered by funds the maker cannot withdraw.
- Order amounts are confidential, so the accounting is conservative: `create_escrow` reserves the worst case (`max_order_size`), and settle publicly changes nothing except closing the reservation. The unspent part of the reservation (`max_order_size - owed`) stays inside the pool change note as surplus (`amount - booked`).
- Rebalancing is the only place surplus becomes public liquidity again: `rebalance_liquidity` restructures pool notes (many in, many out) and lets the maker declare a public `credit`, adding exactly that much of the spent notes' surplus to `available_liquidity`. Timing and granularity are maker-chosen; a zero credit restructures the pool (merge, split, re-blind) with no public effect.
- `max_order_size` is immutable per pair: cancel must release exactly what create_escrow reserved. It is denominated in the destination asset. `escrow_open` proves the reservation covers the order at the public window's highest price.
- Each pair also fixes an absolute `price_tolerance = X` and a private-proof-enforced `min_order_amount`. For public instruction floor `F`, escrow creation accepts the live price in `[F, F + 2X]`; the taker's private `min_price` must be in `[F, F + X]`.
- Only the maker fills: settle requires the pair authority's signature. The taker's paths are settle-by-maker before expiry or unilateral cancel after; the taker's worst case is funds reserved for `expiry_slots`, then cancel.
- Orders settle in FIFO order per pair. Refusing the head prevents later settlement on that pair until expiry and queue advancement, costing the maker subsequent business. The maker still supplies the settlement proof; execution is not guaranteed. See [Order Queue](#order-queue).
- Deposit amounts are public, and the deposit itself is a proven transact: SPP cannot verify an owner signature on a proofless deposit, so a proofless deposit cannot carry the `booked` data hash. The depositor first shields the amount to its own address with a standard proofless deposit; `deposit_liquidity` then spends that note, and a `pool_deposit` proof binds the transaction's only output to a pool note that holds and books exactly the deposited amount. The pool note's blinding derives from a depositor-chosen seed, and the note is encrypted to the pool-role viewing key, so the maker discovers it like any other pool note. Pool confidentiality comes from deposit, withdraw and rebalance output notes, whose blindings derive from private seeds, and from confidential `booked` values. A settle's pool change blinding derives from the order opening, so the taker of that order can compute it (see Settlement recovery). The only encrypted handoff is the order UTXO data at `create_escrow`.
- `execution_price` is public and snapshotted in the escrow account. The coarse `public_price_floor` is instruction data and gates escrow creation; the exact `min_price` is encrypted to the maker and evaluated only in settlement. Settlement privately fills when `execution_price >= min_price`, otherwise it refunds the fixed source amount.
- The payout destination stays confidential: the proof checks that the recipient owner-hash equals the taker's source UTXO owner. It appears only in the order UTXO's composite data hash and encrypted maker handoff.
- The `escrow_authority` and `pool_authority` nullifier secrets are hardcoded to 0: escrow- and pool-note spend linkage is already public (`escrow_utxo_hash` lives in the escrow account, deposit amounts are public), and spends are gated by the proofs, the signer checks, and the liquidity accounting.

## Rust Circuits and Builds

The six application circuits live in [`program/src/circuits/`](program/src/circuits)
behind the program crate's `circuits` feature. They use the `zolana-program`
Rust circuit SDK, following the timelock escrow example: `escrow_open`,
`pool_settle`, `escrow_cancel`, `pool_deposit`, `pool_withdraw`, and
`pool_rebalance`. The SDK proves them with arkworks Groth16. The shielded-pool
transfer proof still comes from the SPP prover.

The program verifies application proofs through generated modules in
[`program/src/verifier/`](program/src/verifier). Each module defines its public
inputs and verifier; its `.vk.rs` companion contains the verifying key and setup
metadata. The SDK prepares the same public inputs when generating a proof.

Run `just build-dynamic-swap-program` to compile the circuits, generate keys and
verifier modules, and build the SBF program. `just ensure-dynamic-swap-keys`
prepares just the circuits and keys; `just regen-dynamic-swap-keys` updates those
outputs after a circuit change. Build artifacts, including each circuit's
`.r1cs`, `.pk`, and `.pk.sha256`, live in `target/zk/dynamic-swap-program`.
`just test-zolana-program-release` checks the generated verifier modules against
the committed files and runs the Rust circuit tests.

These recipes use the SDK's deterministic insecure test setup (`--test`), which
is unsafe for production. A deployment needs its own setup and matching generated
verifier modules; see the [ZK program SDK setup documentation](../../sdk-libs/program/README.md#keys-for-a-deployment).

## Instructions

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | create_pair | 1 | Creates a unidirectional trading pair. Alongside the existing authority, assets, expiry, handoff key, receipt owner, and destination-denominated `max_order_size`, it stores immutable nonzero `price_tolerance` and `min_order_amount`, and initializes `head_order_id = next_order_id = 0`. `price` must be at least the tolerance. | — | pair account (created) | Pair authority signs (fee payer) |
| 2 | update_price | 2 | Updates `price`; it must remain nonzero and at least `price_tolerance`. | — | pair account | Pair authority signs |
| 3 | deposit_liquidity | 3 | Moves a public `amount` of the depositor's shielded destination asset into a new pool UTXO owned by the pair's `pool_authority` PDA, with `booked = amount` in its note data. The depositor first shields exactly `amount` to its own address (a proofless SPP deposit, which cannot carry the `booked` data hash). One `pool_deposit` proof (SPP shape IN1_OUT2, the second output compact padding) binds the transact's only input to a note holding exactly `amount` of the destination asset that is not a pool note (the program signs as the `pool_authority`, so a pool-owned source would re-book liquidity the pool already holds), and its only output to a pool note with `amount = booked = amount`. The transact carries no interface transfer. The program verifies the proof, applies `available_liquidity += amount`, and signs the transact for the `pool_authority`, which owns the data-bearing note. A zero amount is rejected. | — | pair account | Permissionless: the depositor owns the spent note and signs (fee payer) |
| 4 | withdraw_liquidity | 4 | One 1-in/1-out `pool_withdraw` proof (SPP shape IN1_OUT2, the second output compact padding) spends one pool UTXO into a pool change UTXO (back to `pool_authority`, with a maker-held private blinding and `booked_out = booked_in - amount`; the proof rejects a negative result) and a public `amount` unshielded to the authority's SPL token account. Rejects `amount = 0` and `amount > available_liquidity`; `available_liquidity -= amount`. | — | pair account | Pair authority signs |
| 5 | rebalance_liquidity | 5 | One `pool_rebalance` proof restructures the pool: it spends one to five pool UTXOs into one to four pool UTXOs (back to `pool_authority`, maker-held private blindings). The proof checks `sum(amount_out) = sum(amount_in)`, per output `booked <= amount`, and, for the public input `credit`, `sum(booked_out) = sum(booked_in) + credit`. The program applies `available_liquidity += credit`. `credit = 0` restructures with no public effect (merge, split, re-blind). The circuit is compiled once at the largest supported shape (IN5_OUT4); unused slots hold dummy notes. | — | pair account | Pair authority signs |
| 6 | create_escrow | 6 | Creates and prices an exact-input sell escrow at the back of the pair's order queue: `order_id = pair.next_order_id`, then `next_order_id += 1`; the escrow account is the PDA `["escrow", pair, order_id.to_le_bytes()]`. Stores `expires_at = current_slot + expiry_slots`, rejecting overflow. Instruction data carries `public_price_floor = F`; the program rejects unless `F <= pair.price <= F + 2 * price_tolerance` and the fixed reservation is available. The IN1_OUT2 proof privately enforces `order_amount >= min_order_amount`, `F <= min_price <= F + price_tolerance`, and `order_amount * (F + 2 * price_tolerance) <= max_order_size`; it does not check the live price or encrypted handoff delivery. The order data hash commits `Poseidon(recipient_owner_hash, min_price)`, and the SDK's encrypted handoff includes both values. | — | pair account, user escrow account (created) | Taker signs (fee payer) |
| 7 | settle | 7 | Resolves the order at the queue head (`order_id == pair.head_order_id`, else `NotQueueHead`) before expiry and advances the head, with a 2-in/3-out proof (SPP shape IN2_OUT4, the fourth output compact padding). The circuit derives `fills = execution_price >= min_price`. On fill, the recipient gets `order_amount * execution_price` destination tokens and the maker gets the fixed source amount. On refund, the recipient gets the fixed source amount, the pool amount is unchanged, and the maker gets a real zero-amount source UTXO. Both outcomes return pool change, reduce `booked` by `max_order_size`, apply the same public state delta, and expose the same transaction shape. | — | pair account, user escrow account (closed) | Pair authority signs; the destinations are fixed by the proof |
| 8 | cancel | 8 | Refunds one escrow after expiry. An order at the head advances the head and closes; an order behind the head closes. An order ahead of the head stays as a refunded cancellation marker (`cancelled = 1`) until `skip_expired` passes it. A marker cannot be cancelled again (`EscrowCancelled`). One 1-in/1-out `escrow_cancel` proof (SPP shape IN1_OUT2, the second output compact padding) spends the order UTXO back to the confidential recipient committed in its data hash: the full `order_amount` in the source asset, with the refund blinding derived from the order opening (see Settlement recovery). Applies `available_liquidity += max_order_size` and `open_reservations -= 1` exactly once. `rent_recipient` must be the escrow's `owner`. | — | pair account, user escrow account (closed or marked cancelled) | Permissionless: only a holder of the order UTXO data (the taker, or the maker via the handoff) can build the proof, and the destination is fixed by the proof |
| 9 | skip_expired | 9 | Advances the queue head by one past the head order once it can no longer settle: an expired open order retains its escrow and reservation for a later refund, and a cancellation marker closes with its rent returned to the escrow `owner` (`rent_recipient`). Rejects an order that is not the head (`NotQueueHead`) or an open head that has not expired (`NotYetExpired`). Requires no proof or CPI. | — | pair account, user escrow account (closed if a marker) | Permissionless |

## Liquidity Accounting

Per-note invariant: `0 <= booked <= amount`. Global invariant:
`sum(booked) >= available_liquidity + open_reservations * max_order_size`, which
together give `sum(pool UTXO amounts) >= available_liquidity + open_reservations *
max_order_size`.

| Instruction | available_liquidity | open_reservations | actual pool total |
|-------------|-----------------|-------------------|-------------------|
| deposit_liquidity | += amount | — | += amount |
| withdraw_liquidity | -= amount (reject if amount > bound) | — | -= amount |
| rebalance_liquidity | += credit | — | — |
| create_escrow | -= max_order_size (reject if bound < max_order_size) | += 1 | — |
| settle | — | -= 1 | -= owed on fill; unchanged on refund |
| cancel | += max_order_size | -= 1 | — |
| skip_expired | — | — | — |

The notes record the `booked` bookkeeping and the proofs maintain it: a
deposit starts with `booked = amount`, a withdrawal consumes booked value, a
settle moves up to `max_order_size` out of booked (clamped at zero) while only
`owed` leaves the note, and a rebalance raises booked by the declared public
`credit`, capped by the spent notes' surplus (`sum(amount) - sum(booked)`).
The credit is bounded by surplus that is provably present and not yet counted,
so no value is counted twice; the other transitions only lower booked or match
a public delta, so the bound stays a lower bound on the pool total. Settle does
not change the bound, so the public record of the maker's liquidity is
deposits, withdrawals, and the credits the maker publishes.

## State Machine

An escrow starts open (`cancelled = 0`). Creation stores the absolute deadline
`expires_at = current_slot + pair.expiry_slots` using checked arithmetic, before
accepting funds. `settle` accepts `slot <= expires_at`; `cancel` and
`skip_expired` accept an open order only at `slot > expires_at`.

| State and queue position | Instruction | Escrow result | Queue result | Reservation result |
|--------------------------|-------------|---------------|--------------|--------------------|
| open at the head, not expired | `settle` | closes after the proven fill or price-based refund; rent returns to owner | head advances by one | consumed by settlement |
| open at the head, expired | `cancel` | refunds the source amount and closes; rent returns to owner | head advances by one | released to available liquidity |
| open behind the head, expired | `cancel` | refunds the source amount and closes; rent returns to owner | unchanged | released to available liquidity |
| open ahead of the head, expired | `cancel` | refunds the source amount and becomes a marker (`cancelled = 1`) | unchanged | released to available liquidity |
| open at the head, expired | `skip_expired` | stays open and refundable | head advances by one | retained until cancellation |
| cancellation marker at the head | `skip_expired` | closes; rent returns to owner | head advances by one | unchanged; already released |

`owed = order_amount * execution_price`; `max = pair.max_order_size`.
Settlement and cancellation both spend the order UTXO, so only one can succeed.
A cancellation marker is already refunded and cannot settle or cancel again.
A failed proof, transfer CPI, or checked arithmetic rolls back the transaction,
including queue and liquidity updates.

## Order Queue

Each pair keeps two counters, initially zero. `next_order_id` is the ID assigned
by `create_escrow` and then incremented; `head_order_id` is the only order
`settle` accepts. IDs increase with checked arithmetic and are not reused.
`head_order_id <= next_order_id`, and equality means the queue is empty. Expired
orders behind the head can still retain escrows and reservations pending refund.

An escrow account is the PDA `["escrow", pair, order_id.to_le_bytes()]`. The
account stores its `order_id`, pair, order UTXO hash, recorded execution price,
absolute `expires_at`, rent owner, and cancellation flag. The queue metadata
is public. Its enforcement adds no capital-note openings to the public state;
the maker builds settlement proofs using its private pool notes.

The escrow layout replaces `created_at` with `expires_at` at the same offset,
account size (128 bytes), and discriminator. Existing escrow accounts require
explicit conversion before an upgrade; reading them as the new layout would
treat their creation slot as their deadline. Use a fresh example deployment,
or drain existing escrows before upgrading. This example includes no migration.

Opening is atomic: escrow creation, counter increment, reservation, and source
transfer succeed together. The program derives the expected PDA using the live
`next_order_id`. Concurrent users may prepare the same address; a losing
transaction must be rebuilt for the current counter. The ID is outside the
application proof, so the proof can be reused while its other inputs remain
valid.

The head advances one position at a time through settlement, cancellation of
the expired head, or permissionless `skip_expired`. There is no maker-controlled
skip for an unexpired order. Skipping an expired open order preserves the
escrow and reservation: `cancel` can later refund it after the queue has moved
on. Cancelling an expired order ahead of the head retains its refunded marker
so the head can later find that queue position. Removing that marker returns
its rent and does not release its reservation again.

An order's deadline is fixed when it opens. With immutable `expiry_slots` and
creation slots from the Clock, deadlines are nondecreasing in order ID. Waiting
behind a stalled head does not extend a user's deadline, and refunds do not
depend on settling earlier orders. Deposits, rebalances, and withdrawals within
the available-liquidity bound remain available while settlement is stalled.

Refusing the head prevents subsequent settlement on that pair until the head
expires and the queue advances. The cost is lost trading opportunity rather
than guaranteed execution or a fixed penalty per refused order. The maker can
resume after expiry and can continue using other pairs. Several orders can
expire during the same stall, so their delays overlap.

### Order handoff limitation

The SDK encrypts the order opening to `maker_encryption_pubkey`. The current
`escrow_open` proof checks the committed recipient, amount, and minimum price;
it does not prove that the configured maker key can decrypt a matching opening.
A valid commitment with an unreadable handoff can therefore halt the pair until
expiry. Verifiable delivery is a prerequisite for relying on FIFO against
hostile order creators and is outside the queue implementation. Minimum size
and admission cost price processing work but do not establish decryptability.

## Settlement recovery

SPP derives every output blinding of a transaction, and its private transaction
blinding, from one private seed and the first published nullifier. Settle uses
`blinding_seed = Poseidon("DSTX", order_blinding)` and cancel uses
`Poseidon("DCNL", order_blinding)`, each tag encoded as its 32-bit ASCII
integer. The order UTXO is input 0 of both and is owned under the public
zero-secret nullifier key, so the taker computes its nullifier and every
blinding from the order opening it created: the settle payout and the cancel
refund (output `0` of each) are known before either transaction lands, without
trusting a ciphertext. Settle's other outputs, the pool change (`1`) and the
maker receipt (`2`), derive from the same seed, so the taker can compute their
blindings too.

The native program reads the first nullifier from SPP input 0. The generated
verifiers hash the public fields followed by `private_tx_hash`:
`Poseidon(execution_price, order_hash, destination_asset,
pool_authority_owner_hash, max_order_size, receipt_owner_hash, first_nullifier,
private_tx_hash)` for settle and `Poseidon(order_hash, first_nullifier,
private_tx_hash)` for cancel. The circuits check the same value, so
neither the maker nor a canceller can substitute a seed or nullifier that
defeats recovery.

## Future Work

1. allow more taker input utxos in create_escrow
2. batch settlement by the maker (one proof spending the pool UTXO and N order UTXOs)
3. withdrawal of multiple UTXOs
