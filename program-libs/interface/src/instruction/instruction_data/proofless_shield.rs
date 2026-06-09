use borsh::{BorshDeserialize, BorshSerialize};

/// Public deposit without a proof (spec: `proofless_shield`, tag 1).
///
/// The program hashes the recipient's UTXO from these fields plus the settled
/// deposit amount/asset, inserts the hash into the UTXO tree, and indexes it
/// under `bootstrap_view_tag`. The amount is taken from the actual public
/// deposit (not a field here), so a depositor cannot mint a UTXO worth more
/// than they deposited. No proof, no encryption — fully public.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProoflessShieldData {
    /// Recipient's `owner_hash`, written directly (spec: `Utxo.owner`).
    pub owner: [u8; 32],
    /// UTXO blinding (field element).
    pub blinding: [u8; 32],
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
