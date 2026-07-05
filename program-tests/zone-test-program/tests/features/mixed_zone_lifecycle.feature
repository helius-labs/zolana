Feature: Mixed zone lifecycle across owners
  One internally consistent run over a single validator that exercises every
  proof-bearing zone instruction's happy path -- zone_transact over both the
  eddsa rail (full lifecycle: deposit, transfer with wallet-sync discovery and
  full-struct UTXO assertions, withdrawal) and the P256 rail, merge_zone
  (consolidation), and zone_authority_transact (permanent-delegate re-ownership)
  -- alongside proofless zone deposits, plus the proof-rejection negatives for
  every proof-bearing zone instruction.

  Invariants (mirroring spp mixed_lifecycle):
  - A zone deposit makes one zone-owned SOL UTXO spendable for its recipient.
  - A zone transfer / withdrawal each consume two of the sender's spendable zone
    UTXOs; the recipient and the sender's change become spendable only after that
    owner syncs.
  - A merge consumes N of the sender's same-asset zone UTXOs into one consolidated
    zone output (discovered on-chain by inclusion proof, not by wallet sync, since
    the merged output carries an opaque zone-chosen merge_view_tag sync has no
    scan for).
  - The merge_view_tag is opaque to SPP: every merge in this suite reuses the
    same non-field-element tag, and consecutive merges with the same tag must
    both succeed (replay protection comes from the input nullifiers).
  - A zone authority transfer consumes one of the source's zone UTXOs and re-owns
    it to the recipient, skipping the owner's spend signature.
  - The invalid-proof transfer/merge negatives borrow (do not consume) two of
    alice's spendable UTXOs, so alice is kept funded with >= 2 when they run.
  - Every proof-bearing happy path needs the zone config enabled, so they all run
    before the disabled-config negative (which permanently disables the flag).

  Actors:
  - alice: eddsa rail. 6 deposits; consumes 2 (transfer) + 2 (withdrawal) and
    retains 2 for the borrow-only invalid-proof negatives.
  - bob: recipient of alice's eddsa transfer.
  - carol: P256 rail. 2 deposits; consumes 2 in the P256 transfer to dave.
  - gary: 2 deposits; both consumed by the merge.
  - fred: 4 deposits; consumed 2 + 2 by the two tag-reusing merges.
  - henry: 1 deposit; re-owned to ivan by the zone authority.
  - jane / kyle: 1 deposit each, for the authority bad-proof / disabled negatives.

  Background:
    Given a fresh shielded pool

  Scenario: Config, deposits, eddsa/P256 transfers, merge, authority transact, withdrawal, and proof rejections
    When the authority creates an enabled zone config
    Then the zone config is owned by the authority and enabled

    # alice is an eddsa-rail owner (signs her own zone transfers). Fund her with
    # six zone UTXOs: two for the transfer, two for the withdrawal, two retained
    # for the (non-consuming) invalid-proof negatives.
    Given alice with shielded solana keypair
    When alice zone-shields 1000000000 lamports of SOL
    Then alice holds a 1000000000 lamport SOL zone UTXO
    When alice zone-shields 1000000000 lamports of SOL
    When alice zone-shields 1000000000 lamports of SOL
    When alice zone-shields 1000000000 lamports of SOL
    When alice zone-shields 1000000000 lamports of SOL
    When alice zone-shields 1000000000 lamports of SOL

    # eddsa zone transfer alice -> bob (consumes two of alice's UTXOs).
    When alice zone-transfers 300000000 lamports of SOL to bob
    Then the eddsa signer authorized the zone transfer
    When bob syncs
    Then bob's UTXOs match

    # P256 zone transfer carol -> dave. carol is a default (P256-rail) owner whose
    # spends are authorized inside the proof; consumes two of carol's UTXOs.
    When carol zone-shields 1000000000 lamports of SOL
    When carol zone-shields 1000000000 lamports of SOL
    When carol zone-transfers 200000000 lamports of SOL to dave over the P256 rail
    Then the proof authorized the zone transfer
    When dave syncs
    Then dave's UTXOs match

    # merge_zone consolidation: gary consolidates two same-asset zone UTXOs into one.
    When gary zone-shields 1000000000 lamports of SOL
    When gary zone-shields 1000000000 lamports of SOL
    When the zone consolidates 2 of gary's SOL zone UTXOs
    Then gary holds one consolidated zone SOL UTXO

    # merge_view_tag reuse: every consolidation is tagged with the same opaque
    # non-field-element constant, so fred's two consecutive merges (different
    # inputs, same tag, which also repeats gary's tag above) must both succeed.
    When fred zone-shields 1000000000 lamports of SOL
    When fred zone-shields 1000000000 lamports of SOL
    When fred zone-shields 1000000000 lamports of SOL
    When fred zone-shields 1000000000 lamports of SOL
    When the zone consolidates 2 of fred's SOL zone UTXOs
    Then fred holds one consolidated zone SOL UTXO
    When the zone consolidates 2 of fred's SOL zone UTXOs
    Then fred holds one consolidated zone SOL UTXO

    # zone_authority_transact: the zone authority re-owns henry's zone UTXO to ivan
    # (no owner signature; config must be enabled, so this precedes the disabled
    # negative below).
    When henry zone-shields 1000000000 lamports of SOL
    When the zone authority transacts henry's zone UTXO to ivan
    Then the zone authority transition is applied and ivan holds the re-owned zone UTXO

    # zone withdrawal: alice unshields a public amount (consumes two of alice's).
    When alice zone-withdraws 250000000 lamports of SOL

    # Proof-rejection negatives. alice still holds two spendable UTXOs (the
    # transfer/merge negatives borrow them without consuming); jane and kyle each
    # hold a fresh zone UTXO their authority negative builds from.
    Then a zone transfer with an invalid proof is rejected
    Then a zone merge with an invalid proof is rejected
    When jane zone-shields 1000000000 lamports of SOL
    Then a zone authority transact on jane's zone UTXO with a bad proof is rejected
    When kyle zone-shields 1000000000 lamports of SOL
    Then a zone authority transact on kyle's zone UTXO is rejected when disabled
