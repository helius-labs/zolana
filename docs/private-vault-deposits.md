# Private Vault Deposits: Designs

The default ring is confidential: transfer senders and recipients are public, amounts are
encrypted. A direct vault deposit (e.g. Kamino kVault) publishes the amount, so private
deposits need the vault to see only aggregates. SPP itself is not changed by any design below.

| # | Design | How | Hides | Trust | Status |
|---|--------|-----|-------|-------|--------|
| 1 | Operator batch | Users send USDC to receipt UTXOs owned by an adapter PDA; an operator consolidates them, deposits the total into the vault, and pays out shares pro-rata. | Amounts from the public | Operator sees each amount; consolidated funds depend on its liveness | Not pursued |
| 2 | Homomorphic sum | Users publish encrypted amounts; a decryptor reveals only the total. | Amounts from the decryptor | Threshold or TEE key holder | Not pursued: value leaves the pool only through a proof whose author knows each input, so it needs SPP changes |
| 3 | RFQ market maker | Users swap USDC for vault shares with a market maker in one co-signed `transact` at the vault rate plus a fee; the maker rebalances against the vault in aggregate. | Amount, direction, asset | Maker (TEE) sees each trade it fills | Minimal version: [sdk-tests/kamino-vault/rfq](../sdk-tests/kamino-vault/rfq/spec.md) |
| 4 | Committed-liquidity pair | A vault pair on [dynamic swap](../sdk-tests/dynamic-swap/swap_program.md): escrowed orders, the maker's share pool with fixed-size reservations, maker settlement before expiry. | Amount | Maker liveness until expiry | Async tier for users who cannot stay online |
| 5 | kVault intents | A separate program for a fixed set of kVaults: orders collect per period; the program executes the maker's net kVault operation per vault by CPI and records the realized rate; each order fills at that rate. Orders hide their vault and direction. The maker holds no inventory and no price risk. | Amount, vault, direction, outcome | Maker liveness until expiry | [spec](../sdk-tests/kamino-vault/intent/spec.md) |

## Notes

- Designs 1 and 2 pool users' funds, which forces a merge step that only the operator can
  complete. Designs 3 to 5 do not merge funds; each trade is between one user and the maker.
- The maker's working capital sits in vault shares and earns the vault yield.
- Exits: delayed exits let the maker withdraw from the vault just in time; an instant exit
  tier from a buffer can charge a premium that rises as the buffer empties.
- Running the maker in a TEE (Nitro, shared KMS key) hides trades from its operator, and
  attestation shows which pricing, fill, and rebalancing policy it runs.
