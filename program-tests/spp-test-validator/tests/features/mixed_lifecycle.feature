Feature: Mixed-lifecycle traffic across three owners
  A long, internally consistent run that mixes deposits, shielded transfers, SOL
  withdrawals (unshield), and merge-service consolidations across alice, bob, and
  carol.

  Invariants used to keep the ledger consistent:
  - Every SOL transfer consumes two of the sender's spendable SOL UTXOs and emits
    the sender's SOL change plus one recipient UTXO; both become spendable for
    their owner only after that owner runs `syncs`.
  - Every withdrawal consumes two spendable SOL UTXOs, sends the public amount out
    of the pool to a fresh external account, and keeps the sender's SOL change.
  - A merge consumes N freshly deposited (deposit-origin) spendable SOL UTXOs into
    one consolidated note, which is not spent again in this scenario.
  - To avoid depending on transfer change re-entering the spendable set, every
    consuming step is fed by deposits made just before it.
  #
  # State-changing transaction count: 53
  #   deposits:    38  (phases 1, 3, 5, 7)
  #   transfers:    8  (phases 2, 6)
  #   withdrawals:  3  (phases 4, 8)
  #   merges:       4  (phases 4, 8)
  # Syncs, UTXO-match asserts, and registrations are not counted.

  Background:
    Given a fresh shielded pool

  Scenario: Fifty mixed transactions across three owners
    # alice and bob opt into the merge service so the authority can consolidate
    # their freshly deposited SOL UTXOs later. carol stays transfer/withdraw only.
    Given alice registers for the merge service
    And bob registers for the merge service

    # Phase 1 -- front-loaded deposits (tx 1-12): four 1e9 SOL UTXOs each.
    Given alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And carol deposits 1000000000 lamports of SOL
    And carol deposits 1000000000 lamports of SOL
    And carol deposits 1000000000 lamports of SOL
    And carol deposits 1000000000 lamports of SOL

    # Phase 2 -- first transfer wave (tx 13-16). Each consumes two of the sender's
    # phase-1 deposits and gifts the recipient one UTXO.
    # Spendable SOL after: alice 4-2-2=0, bob 4-2=2, carol 4-2=2.
    When alice transfers 300000000 lamports of SOL to bob
    And alice transfers 350000000 lamports of SOL to carol
    And bob transfers 400000000 lamports of SOL to carol
    And carol transfers 500000000 lamports of SOL to bob
    # bob and carol sync to confirm the recipient UTXOs + their own change; both
    # only ever sent one transfer, so their decrypted set is fully tracked.
    When bob syncs
    Then bob's UTXOs match
    When carol syncs
    Then carol's UTXOs match

    # Phase 3 -- top-up deposits before the merges (tx 17-24): four fresh 1e9 SOL
    # UTXOs each for alice and bob (deposit-origin, for the consolidations).
    Given alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL

    # Phase 4 -- first consolidation + withdrawal wave (tx 25-29).
    # alice spendable before: 0 + 4 deposits = 4 -> merge 4 leaves 0.
    # bob spendable before: 2 (from phase 2, unspent) + 4 deposits = 6.
    When the merge service consolidates 4 of alice's SOL UTXOs
    Then alice holds one consolidated SOL UTXO
    When the merge service consolidates 4 of bob's SOL UTXOs
    Then bob holds one consolidated SOL UTXO
    # bob: 6 - 4 merged = 2 spendable -> one withdrawal consumes 2 -> 0.
    When bob withdraws 300000000 lamports of SOL
    # carol: 2 spendable (phase-2 leftovers) -> one withdrawal consumes 2 -> 0.
    And carol withdraws 350000000 lamports of SOL

    # Phase 5 -- replenish for the second wave (tx 30-41): four 1e9 SOL UTXOs each.
    Given alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And carol deposits 1000000000 lamports of SOL
    And carol deposits 1000000000 lamports of SOL
    And carol deposits 1000000000 lamports of SOL
    And carol deposits 1000000000 lamports of SOL

    # Phase 6 -- second transfer wave (tx 42-45).
    # alice 4 -> 2 -> 0, bob 4 -> 2, carol 4 -> 2.
    When alice transfers 450000000 lamports of SOL to carol
    And alice transfers 300000000 lamports of SOL to bob
    And bob transfers 400000000 lamports of SOL to carol
    And carol transfers 500000000 lamports of SOL to alice
    # carol only sent one transfer this wave, so its decrypted set is fully tracked.
    When carol syncs
    Then carol's UTXOs match

    # Phase 7 -- final top-up before the closing consolidations (tx 46-48):
    # three fresh 1e9 SOL UTXOs each for alice and bob.
    Given alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And alice deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL
    And bob deposits 1000000000 lamports of SOL

    # Phase 8 -- closing consolidations + final withdrawal (tx 49 and the merges).
    # alice spendable: 0 + 3 deposits = 3 -> merge 3 leaves 0.
    # bob spendable: 2 (phase-6 leftover) + 3 deposits = 5 -> merge 3 leaves 2.
    When the merge service consolidates 3 of alice's SOL UTXOs
    Then alice holds one consolidated SOL UTXO
    When the merge service consolidates 3 of bob's SOL UTXOs
    Then bob holds one consolidated SOL UTXO
    # bob: 2 spendable left -> final withdrawal consumes 2 -> 0.
    When bob withdraws 300000000 lamports of SOL
