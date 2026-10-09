# Private kVault Deposits

Users can deposit into and exit from Kamino kVaults from private balances without revealing transaction amounts.

1. Users swap USDC for kVault shares with the market maker through a private RFQ inside the shielded pool, at the vault's exchange rate plus a small fee.
2. The market maker deposits into the vault in aggregate on its own schedule, so Kamino only sees its net flow and individual amounts stay private.
3. Exits work the same way in reverse.
4. The market maker could run in a TEE, so its operator doesn't see user amounts either.

Each swap is two SPP `transact` instructions in one Solana transaction, one proved by each side with its own keys (see [RFQ Swap](#rfq-swap-depositwithdrawal)). No custom program is involved: the vault is the unmodified kVault program, and the share mint is registered with `create_spl_interface`.

## Actors

| Actor | Role | Trust |
|-------|------|-------|
| User | Holds shielded USDC or shares, requests quotes, proves the user transfer, signs the swap | Trusts nobody for funds: signs only after checking the maker transfer |
| Market maker | Quotes, proves the maker transfer, assembles and pays for the transaction, holds share and USDC inventory, rebalances against kVault | Trusted for liveness and exit timing, not for funds or price |
| kVault | Mints and burns shares against USDC at `shares_issued / AUM` | Public program; its state is the price oracle |
| Privacy program | Verifies each transfer's proof, enforces balance per asset and each input owner's signature | Protocol |

## RFQ Swap (Deposit/Withdrawal)

1. User: request quote. The user sends the market maker the direction (deposit or exit) and `amount_in`.

2. Market maker: quote. The market maker returns:
   1. `amount_out` at the vault rate minus its fee
   2. its addresses
   3. `max_user_inputs`, the widest user transfer that still fits next to its own transfer in one v1 transaction (4,096 bytes, 64 addresses, 1.4M compute units)

3. User: accept quote, create user transfer instruction. The user generates a transact zk proof that:
   1. spends N of its UTXOs (N <= `max_user_inputs`)
   2. creates 2 UTXOs: `amount_in` for the market maker, change for itself

   User sends the market maker only the instruction.

4. Market maker: create maker transfer instruction and send transaction.
   1. The market maker checks the user transfer: N <= `max_user_inputs`, 2 outputs, no interface transfers, `amount_in` addressed to it.
   2. It generates a transact zk proof that spends M of its inventory UTXOs and creates 1 + C UTXOs: `amount_out` for the user, C change UTXOs for itself (C >= 1, more when lane growth splits the change).
   3. It builds one transaction holding the user transfer and the maker transfer.
   4. The user signs it after checking that the maker transfer pays it the quoted amount.
   5. The market maker signs and sends it.

Atomicity is the Solana transaction: both transfers land or neither does. Non-extractability: each input owner is a signer of the transaction, and each signature covers the whole message, so neither transfer can be sent without the other.

Two transacts against one tree in one transaction are valid: the maker transfer's proof references a root from the tree's root history, which the user transfer's append does not evict, and the two transfers create distinct nullifier PDAs.

### Privacy

| Field | Visible to | Reason |
|-------|------------|--------|
| User address | Public | The user signs the transaction as owner of the user transfer's inputs |
| Market maker address | Public | It pays the fee and signs as owner of the maker transfer's inputs and cache writer |
| Swap amount | User, market maker | Only in output ciphertexts and commitments; the market maker learns it from the user transfer output addressed to it |
| User balance, other UTXOs | User | The market maker sees only the user transfer instruction and decrypts only its own output |
| Direction (deposit or exit) | User, market maker | Both transfers move shielded UTXOs; the transaction shape is the same both ways |
| Asset | User, market maker | Hidden in the UTXO; trading with the vault's market maker still suggests the pair |
| Rebalance amounts | Public | Aggregated over many users, decoupled in time from any single swap |






## Risks

- Timing: a rebalance shortly after a single swap links the two amounts. The market maker should batch and delay.
- Exit liquidity: exits wait for the market maker; `withdraw_from_available` only pays from idle vault liquidity.
- Inventory: a fill fails when the market maker holds too few shares or too little USDC in one UTXO.
- Rate drift between quote and signing: the user re-reads the vault and rejects a fill below the current rate minus the fee.
- Cost: a swap pays for two proof verifications and two nullifier PDAs.

## Future Work

1. Instant exit tier priced with a utilization premium, served from market maker USDC inventory.
2. Asynchronous orders through an adapter program, so the user need not be online to sign.
3. Other pairs with a redeemable rate in a program account (liquid staking tokens, other vaults).
4. Running the market maker inside a TEE, so its operator does not learn individual swap amounts. Key custody does not need it: no user key reaches the market maker.
