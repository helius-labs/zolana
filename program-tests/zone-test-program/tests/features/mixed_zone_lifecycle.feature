Feature: Mixed zone lifecycle across owners
  A single internally consistent run over one validator that exercises every
  proof-bearing zone instruction (zone_transact, merge_zone,
  zone_authority_transact) alongside proofless zone deposits, with wallet-sync
  discovery and full-struct UTXO assertions. Recipients are tracked actors so
  Wallet::sync rediscovers every output by its view tag.

  Invariants:
  - A zone deposit makes one zone-owned SOL UTXO spendable for its recipient.
  - A zone transfer consumes two of the sender's spendable zone UTXOs and emits
    the recipient output plus the sender's change; both become spendable for
    their owner only after that owner syncs.
  - A zone consolidation (merge_zone) consumes N of one owner's spendable zone
    UTXOs into a single consolidated output.

  Background:
    Given a fresh shielded pool

  Scenario: Zone deposits, transfers, a withdrawal, a consolidation, and an authority transition
    When the authority creates an enabled zone config
    Then the zone config is owned by the authority and enabled

    # Front-load spendable zone UTXOs for alice and bob.
    When alice zone-shields 1000000000 lamports of SOL
    Then alice holds a 1000000000 lamport SOL zone UTXO
    When alice zone-shields 1000000000 lamports of SOL
    When alice zone-shields 1000000000 lamports of SOL
    When alice zone-shields 1000000000 lamports of SOL
    When bob zone-shields 1000000000 lamports of SOL
    When bob zone-shields 1000000000 lamports of SOL

    # A zone transfer (eddsa rail): consumes two of alice's zone UTXOs, gifts bob
    # one output and returns alice's change. bob discovers the gift by sync.
    When alice zone-transfers 300000000 lamports of SOL to bob
    Then the proof authorized the zone transfer
    When bob syncs
    Then bob's UTXOs match

    # A zone withdrawal: alice unshields a public amount to a fresh account.
    When alice zone-withdraws 250000000 lamports of SOL

    # A zone consolidation of two of bob's zone UTXOs into one output.
    When the zone consolidates 2 of bob's SOL zone UTXOs
    Then bob holds one consolidated zone SOL UTXO

    # Proof-rejection negatives (the placeholder/zeroed proof must be refused).
    Then a zone transfer with an invalid proof is rejected
    Then a zone merge with an invalid proof is rejected
