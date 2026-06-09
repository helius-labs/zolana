use borsh::{BorshDeserialize, BorshSerialize};

/// Public deposit without a proof (spec: `proofless_shield`, tag 1).
///
/// The program hashes the recipient's UTXO from these fields plus the settled
/// deposit amount/asset, inserts the hash into the UTXO tree, and indexes it
/// under `bootstrap_view_tag`. The owner is committed as `owner_utxo_hash =
/// Poseidon(owner, blinding)`, so the recipient is hidden even though the
/// deposit is public. The amount is taken from the actual public deposit (not a
/// field here), so a depositor cannot mint a UTXO worth more than they
/// deposited. No proof, no encryption (amount + asset are public).
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProoflessShieldData {
    /// `owner_utxo_hash = Poseidon(owner, blinding)`. Opaque to the program — it
    /// hides the recipient. The depositor (who knows owner+blinding) records it
    /// off-chain to spend later. A malformed value just yields an unspendable
    /// UTXO (the depositor's loss only).
    pub owner_utxo_hash: [u8; 32],
    /// `program_data_hash` field of the UTXO commitment.
    pub data_hash: [u8; 32],
    /// `policy_data_hash` field of the UTXO commitment.
    pub zone_data_hash: [u8; 32],
    /// `zone_program_id` field of the UTXO commitment.
    pub zone_program_id: [u8; 32],
    /// Recipient bootstrap view tag (`recipient.viewing_pk`); the queue entry
    /// the recipient scans to discover the deposit.
    pub bootstrap_view_tag: [u8; 32],
    /// Public SOL deposit. Exactly one of `public_sol_amount`/`public_spl_amount`
    /// must be set; it becomes the deposited UTXO's amount.
    pub public_sol_amount: Option<u64>,
    /// Public SPL deposit. Exactly one of `public_sol_amount`/`public_spl_amount`
    /// must be set; it becomes the deposited UTXO's amount.
    pub public_spl_amount: Option<u64>,
    /// Cleartext UTXO body for the indexer (spec: no encryption). Opaque to SPP.
    pub cleartext_utxo: Vec<u8>,
}
