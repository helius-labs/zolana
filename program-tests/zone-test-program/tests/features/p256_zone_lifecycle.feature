Feature: P256 zone transact lifecycle
  The P256 zone rail obtains a committed proof from the Go prover server and
  submits it through the zone fixture program to the shielded pool. This runs
  alongside, and does not replace, the existing EdDSA zone lifecycle.

  Background:
    Given a fresh shielded pool

  Scenario: A P256 owner transfers a zone UTXO
    When the authority creates an enabled zone config
    Given piper with shielded P256 keypair
    When piper zone-shields 1000000000 lamports of SOL
    When piper zone-shields 1000000000 lamports of SOL
    Then a P256 zone transfer with an invalid commitment is rejected
    When piper P256-zone-transfers 300000000 lamports of SOL to riley
    Then the P256 proof authorized the zone transfer
    When riley syncs
    Then riley's UTXOs match
