# Private kVault Deposits

Users can deposit into and withdraw from Kamino kVaults with their private balances without revealing amounts.

Flow:
1. Users swap USDC for kVault shares with a market maker through a private RFQ between private balances, at the vault's exchange rate plus a small fee.
2. The market maker deposits into the vault in aggregate on its own schedule, so individual amounts stay private.
3. Withdrawals work the same way in reverse.
4. The market maker could run in a TEE, so its operator doesn't see user amounts either.

The market maker supports a set of swap pairs. A pair is one kVault and its two tokens:
1. Collateral: the token the vault accepts, for example USDC.
2. Shares: the token the vault mints for deposited collateral.

Each swap is one Solana transaction of two private transfer instructions. The user and the market maker prove the transfer themselves so that neither side sees the others private balance.
No custom program is involved, the vault is the unmodified kVault program.

## Actors

| Actor | Role | Trust |
|-------|------|-------|
| User | Holds private collateral or shares, requests quotes, proves the user transfer, signs the swap | Trusts nobody for funds: signs only after checking the maker transfer |
| Market maker | Quotes, proves the maker transfer, assembles and pays for the transaction, holds share and collateral inventory, rebalances against kVault | Trusted for liveness and withdrawal timing, not for funds or price |
| kVault | Mints and burns shares against collateral at `shares_issued / AUM` | Public program; its state is the price oracle |
| Privacy program | Verifies each transfer's proof, enforces balance per asset and each input owner's signature | Protocol |

## RFQ Swap (Deposit/Withdrawal)

1. User: request quote. The user sends the market maker the pair, the direction (deposit or withdrawal) and `amount_in`.

2. Market maker: quote. The market maker returns:
   1. `amount_out` at the vault rate minus its fee
   2. its addresses
   3. `max_user_inputs`, the widest user transfer that still fits next to its own transfer in one v1 transaction (4,096 bytes, 64 addresses, 1.4M compute units)

   The market maker only quotes amounts its inventory can absorb while staying within its target range, so a single swap cannot force a rebalance on its own.

3. User: accept quote, create user transfer instruction. The user generates a transact zk proof that:
   1. spends N of its UTXOs (N <= `max_user_inputs`)
   2. creates 2 UTXOs: `amount_in` for the market maker, change for itself

   The user sends the market maker only the instruction.

4. Market maker: create maker transfer instruction and transaction.
   1. The market maker checks the user transfer.
   2. It generates a transact zk proof that spends M of its inventory UTXOs and creates 1 + C UTXOs: `amount_out` for the user, C change UTXOs for itself (C >= 1).
   3. It builds one transaction containing the user transfer and the maker transfer, and sends it to the user.

5. User: sign transaction. The user checks that the maker transfer pays it the quoted amount, signs the transaction and sends the signature to the market maker.

6. Market maker: send transaction. The market maker adds its signature and sends the transaction.

Atomicity is the Solana transaction: both transfers land or neither does.

### Privacy

| Field | Visible to | Reason |
|-------|------------|--------|
| User address | Public | Signs rfq swap transaction. |
| Market maker address | Public | Signs rfq swap transaction. |
| Swap amount | Private | Private transfers prove state transition with zero knowledge proofs and encrypt amounts. |
| User balance, other UTXOs | Private: User | The user generates her own transfer proof, the market maker can only decrypt her new UTXO.  |
| Direction (deposit or withdrawal) | Private: User, market maker | Private transfers do not reveal the transferred assets. |
| Pair | Public/Private | Private transfers do not reveal the transferred assets. Can be inferred if the maker only supports a single pair. |
| Rebalance amounts | Public | Aggregated over many users, decoupled in time from any single swap |

## Market Maker

1. Setup prepares a pair once, so the market maker can hold its shares privately and quote from its own inventory.
2. Inventory management keeps balance split in multiple UTXOs for concurrent swaps and decides when to rebalance.
3. Rebalancing moves the aggregate net flow of many swaps through kVault, so only aggregate amounts are public.

### Setup

Per pair:

1. Register the share mint in the privacy protocol.

2. Seed inventory.
   1. Deposit collateral into the pair's kVault and receive shares.
   2. Shield the shares, and collateral, into its private balance.

### Inventory

1. Concurrency: configure how many swaps the market maker can serve at the same time.
   1. Problem: a swap spends one of the market maker's UTXOs, and its change is only spendable once the swap lands, so a single balance serves one swap at a time.
   2. Solution: the market maker keeps its inventory split, so quotes can be executed concurrently.
   3. Sizing: the market maker keeps many UTXOs of different sizes, so a few large ones fill a large swap in one transaction while many small ones serve concurrent small swaps.

2. Target balance range: configure per token when a rebalance is triggered.
   1. Problem: every rebalance is a public kVault operation, so a rebalance right after one swap reveals that swap's amount.
   2. Solution: keep balances in target range and rebalances only when a balance leaves it, so a rebalance aggregates many swaps.
   3. Sizing: the range should be wide compared with typical swaps, a max swap size should prevent large swaps which become an issue if these only occur in on pair direction and trigger rebalance with few user interaction.

### Rebalance

1. Trigger. A rebalance runs when a balance leaves its target range: too much collateral and too few shares after net deposits.

2. Rebalance shares: turn collateral into shares.
   1. Unshield the collected collateral.
   2. Deposit it into kVault.
   3. Shield the minted shares.

3. Rebalance collateral: turn shares into collateral.
   1. Unshield shares.
   2. Withdraw from kVault.
   3. Shield the collateral.
