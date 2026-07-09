Feature: Randomized mixed-asset eddsa workload
  A long, internally consistent run that drives deposits, SOL withdrawals, shielded
  transfers (SOL-only, SPL-only, single-input, SOL+SPL mixed, and change-only
  consolidations), and merge-service consolidations across many eddsa actors and
  three SPL assets.

  Every actor is its own eddsa identity that pays and signs its own spends, so the
  run exercises multiple distinct senders and recipients. Merge uses the eddsa owner
  rail: an actor registers under its own ed25519 signing key and the merge authority
  consolidates its SOL UTXOs into one output.

  Each transaction is followed by its strongest full assert (deposit -> deposit
  assert; transfer/consolidate -> sync + full-struct UTXO assert on each involved
  actor; merge -> sync + full-struct UTXO assert + inclusion check; withdrawal ->
  recipient credit + sender UTXO assert). After the run, every actor is synced and asserted
  again, and an on-chain conservation invariant ties the pool's SOL custody and SPL
  vault balances to the net deposited minus withdrawn.

  The seed is random each run and printed at the start; set RINGS_RANDOM_SEED to
  reproduce a specific run.

  Background:
    Given a fresh shielded pool

  Scenario: Fifty randomized eddsa transactions across SOL and three SPL assets
    When a randomized workload of 50 transactions runs
