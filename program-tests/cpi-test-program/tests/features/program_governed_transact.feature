Feature: Program-governed transact through a CPI fixture over Photon
  A shielded SOL note is shielded to a sender on the eddsa rail, then spent through a
  real program-governed transact wrapped by the CPI fixture program (which signs its
  CPI-signer PDA). The transact mints a recipient output carrying the fixture program
  as its per-utxo program_id, exercising the circuit's bindIfSet binding. The recipient
  wallet then discovers the program-governed UTXO by syncing against real Photon.

  Background:
    Given a fresh shielded pool
    Given sender with shielded solana keypair

  Scenario: A program-governed transact mints a recipient output discovered over Photon
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    When sender program-governed transacts to recipient
    When recipient syncs
    Then recipient's UTXOs match

  Scenario: A forged program-governed transact without the program's authorization is rejected
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    Then a forged program-governed transact from sender to recipient is rejected
