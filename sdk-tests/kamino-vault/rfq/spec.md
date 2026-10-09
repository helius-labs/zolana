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
| Market maker | Quotes, proves the maker transfer, assembles and pays for the transaction, holds share and collateral inventory, rebalances against kVault | Trusted for liveness and exit timing, not for funds or price |
| kVault | Mints and burns shares against collateral at `shares_issued / AUM` | Public program; its state is the price oracle |
| Privacy program | Verifies each transfer's proof, enforces balance per asset and each input owner's signature | Protocol |

## RFQ Swap (Deposit/Withdrawal)

1. User: request quote. The user sends the market maker the pair, the direction (deposit or exit) and `amount_in`.

2. Market maker: quote. The market maker returns:
   1. `amount_out` at the vault rate minus its fee
   2. its addresses
   3. `max_user_inputs`, the widest user transfer that still fits next to its own transfer in one v1 transaction (4,096 bytes, 64 addresses, 1.4M compute units)

3. User: accept quote, create user transfer instruction. The user generates a transact zk proof that:
   1. spends N of its UTXOs (N <= `max_user_inputs`)
   2. creates 2 UTXOs: `amount_in` for the market maker, change for itself

   The user sends the market maker only the instruction.

4. Market maker: create maker transfer instruction and transaction.
   1. The market maker checks the user transfer: N <= `max_user_inputs`, 2 outputs, no interface transfers, `amount_in` addressed to it.
   2. It generates a transact zk proof that spends M of its inventory UTXOs and creates 1 + C UTXOs: `amount_out` for the user, C change UTXOs for itself (C >= 1).
   3. It builds one transaction containing the user transfer and the maker transfer, and sends it to the user.

5. User: sign transaction. The user checks that the maker transfer pays it the quoted amount, signs the transaction and sends the signature to the market maker.

6. Market maker: send transaction. The market maker adds its signature and sends the transaction.

Atomicity is the Solana transaction: both transfers land or neither does. Non-extractability: each input owner is a signer of the transaction, and each signature covers the whole message, so neither transfer can be sent without the other.

Two transacts against one tree in one transaction are valid: the maker transfer's proof references a root from the tree's root history, which the user transfer's append does not evict, and the two transfers create distinct nullifier PDAs.

### Privacy

| Field | Visible to | Reason |
|-------|------------|--------|
| User address | Public | The user signs the transaction as owner of the user transfer's inputs |
| Market maker address | Public | It pays the fee and signs as owner of the maker transfer's inputs |
| Swap amount | User, market maker | Only in output ciphertexts and commitments; the market maker learns it from the user transfer output addressed to it |
| User balance, other UTXOs | User | The market maker sees only the user transfer instruction and decrypts only its own output |
| Direction (deposit or exit) | User, market maker | Both transfers move shielded UTXOs; the transaction shape is the same both ways |
| Pair | User, market maker | Hidden in the UTXOs; with one supported pair, trading with the market maker still points to it, so more pairs hide it better |
| Rebalance amounts | Public | Aggregated over many users, decoupled in time from any single swap |

## Market Maker

1. Setup prepares a pair once, so the market maker can hold its shares privately and quote from its own inventory.
2. Inventory management keeps enough balance split for concurrent swaps and decides when to rebalance.
3. Rebalancing moves the net flow of many swaps through kVault, so the vault only sees aggregate amounts.

### Setup

Per pair:

1. Register the share mint in the privacy protocol. `create_spl_interface` for the pair's share mint, so shares can be held in private balances.

2. Seed inventory.
   1. Deposit collateral into the pair's kVault and receive shares.
   2. Shield the shares, and optionally collateral, into its private balance.

### Inventory

1. Concurrency: configure how many swaps the market maker can serve at the same time.
   1. Problem: a swap spends one of the market maker's UTXOs, and its change is only spendable once the swap lands, so a single balance serves one swap at a time.
   2. Solution: the market maker keeps its inventory split, so concurrent quotes do not wait on each other.

2. Keep target balances. The market maker keeps a target balance per token, and a rebalance brings it back into range.

3. Schedule rebalances. Rebalances run on a schedule rather than right after a single large swap, so a public kVault operation cannot be linked to one user.

### Rebalance

1. Decide. Exits are filled first from the collateral that deposits paid in; only the net amount goes through kVault.

2. Rebalance shares: turn collateral into shares.
   1. Unshield the collected collateral.
   2. Deposit it into kVault.
   3. Shield the minted shares.

3. Rebalance collateral: turn shares into collateral.
   1. Unshield shares.
   2. Withdraw from kVault with `withdraw_from_available`.
   3. Shield the collateral.
