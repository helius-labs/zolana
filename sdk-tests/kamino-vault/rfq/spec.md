# Private kVault Deposits

- Users hold Kamino kVault exposure without a public deposit: they swap USDC for kVault shares with a market maker inside the shielded pool, and exit the same way in reverse.
- Every user swap is one co-signed SPP `transact` (IN2_OUT4) with no interface transfers: no token moves in or out of the pool, so no amount, direction or asset is public.
- The price is the vault's on-chain exchange rate minus a fee in bps. The user re-derives the rate from the vault account and checks the decrypted outputs before co-signing.
- kVault only sees the market maker. It deposits and withdraws publicly, in aggregate, on its own schedule.
- No custom on-chain program: the vault is the unmodified kVault program, the swap is a plain SPP `transact`, and the kVault share mint is registered with `create_spl_interface`.

## Actors

| Actor | Role | Trust |
|-------|------|-------|
| User | Holds shielded USDC or shares, requests quotes, co-signs swaps | Trusts nobody for funds: signs only after `verify_quote` passes |
| Market maker | Quotes, builds and proves the swap, holds share and USDC inventory, rebalances against kVault | Trusted for liveness and exit timing, not for funds or price |
| kVault | Mints and burns shares against USDC at `shares_issued / AUM` | Public program; its state is the price oracle |
| Shielded pool | Verifies the swap proof, enforces balance per asset and the user's signature | Protocol |

## Flows

1. Deposit. The user asks for `usdc_in`. The market maker reads the vault, quotes `shares_out = floor(kvault_shares(usdc_in) * (10000 - fee_bps) / 10000)` and builds the transact: inputs are the user's USDC UTXO and its own share UTXO; outputs are shares to the user, USDC to the market maker, and change to both. The user verifies and co-signs; the market maker pays the fee.
2. Rebalance. The market maker unshields its aggregate USDC, calls kVault `deposit`, and shields the minted shares back into inventory.
3. Delayed exit. The user requests an exit of `y` shares off-chain. The market maker unshields shares, calls kVault `withdraw_from_available` for the aggregate, and shields the USDC. The user then swaps `y` shares for `floor(kvault_tokens(y) * (10000 - fee_bps) / 10000)` USDC at the then-current rate.

kVault rounding: shares minted `floor(shares_issued * amount / ceil(AUM))`, tokens pulled `ceil(AUM * shares / shares_issued)`, tokens paid on withdraw `floor(AUM * shares / shares_issued)`.

## Visibility

| Field | Visible to | Reason |
|-------|------------|--------|
| User address | Public | The user co-signs the transact as an owner signer |
| Market maker address | Public | It pays the fee and signs the transact |
| Swap amount | User, market maker | Only in output ciphertexts and commitments |
| Direction (deposit or exit) | User, market maker | Both legs are shielded UTXOs; the transact shape is the same both ways |
| Asset | User, market maker | Hidden in the UTXO; trading with the vault's market maker still suggests the pair |
| Rebalance amounts | Public | Aggregated over many users, decoupled in time from any single swap |

## Risks

- Timing: a rebalance shortly after a single swap links the two amounts. The market maker should batch and delay.
- Exit liquidity: exits wait for the market maker; `withdraw_from_available` only pays from idle vault liquidity.
- Inventory: a fill fails when the market maker holds too few shares or too little USDC.
- Rate drift between quote and co-sign: the user re-reads the vault and rejects a quote below the current rate minus the fee.
- In this demo the market maker proves with the user's nullifier key, as in `sdk-tests/rfq`; a production flow keeps it on the user's side.

## Future Work

1. Instant exit tier priced with a utilization premium, served from market maker USDC inventory.
2. Asynchronous orders through an adapter program, so the user need not be online to co-sign.
3. Other pairs with a redeemable on-chain rate (liquid staking tokens, other vaults).
4. Proving inside a TEE so the user's nullifier key never leaves its device or enclave.
