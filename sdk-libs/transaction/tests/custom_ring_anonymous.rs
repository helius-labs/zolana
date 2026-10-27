use solana_address::Address;
use zolana_keypair::{PublicKey, X25519Pubkey};
use zolana_transaction::Data;

// Context:
// 1. we create transaction history from WalletUtxo types
// 2. Anonymous transaction ciphertexts must be sufficient to create WalletUtxo and be decryptable by the auditor (complete tx), sender (complete tx), recipient (recipient utxo, and needs to know who sent funds)
// 3. Auditor and sender share the tx viewing key.
// 4. Auditor must be able to verifiably decrypt, amount, mint, owner for transaction monitoring
// 5. Decryption performance must be independent from other protocol state.
// 6. Utxo recovery is not guaranteed same as in the default ring

// Questions:
// 1. do we want to verify the sender pubkey for the recipient?
// 2.

// How AnonymousTransferRecipientPlaintext maps to WalletUtxo fields for recipient:
// 1. utxo.owner: PublicKey
//    verified.owner_pubkey
// 2. utxo.asset.asset: Address
//    verified.mint
// 3. utxo.asset.asset_id: u64
//    AssetRegistry lookup by verified.mint
// 4. utxo.amount: u64
//    verified.amount
// 5. utxo.blinding: Blinding
//    unverified.blinding
// 6. utxo.ring_program_id: Option<Address>
//    indexed transaction's ring program, if ring data is present
// 7. utxo.data: Data
//    unverified.data
// 8. nullifier_pubkey: [u8; 32]
//    recipient's shielded address
// 9. utxo_hash: [u8; 32]
//    indexed output_context.hash, checked by reconstruction
// 10. nullifier: [u8; 32]
//     recipient's nullifier key, utxo_hash, and utxo.blinding
// 11. tx_viewing_key: Option<[u8; 32]>
//     recipient's viewing key and this UTXO's nullifier, for a future spend; initially None
// 12. data_hash: Option<[u8; 32]>
//     application-specific hash of unverified.data.utxo_data(), or None
// 13. ring_data_hash: Option<[u8; 32]>
//     ring-specific hash of unverified.data.ring_data(), or None
// 14. tree_id: u16
//     indexed output_context.tree_id
// 15. leaf_index: u64
//     indexed output_context.leaf_index
// 16. latest_tree_id: Option<u16>
//     indexer page's output_tree_id
// 17. slot: u64
//     indexed transaction's slot
// 18. tx_signature: Signature
//     indexed transaction's tx_signature
// 19. slot_index: u32
//     output's position in indexed transaction's output_slots

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferRecipientPlaintext {
    /// Verifiably encrypted monitoring fields.
    pub verified: VerifiedRecipientPlaintext,
    /// Encrypted without circuit enforcement.
    pub unverified: UnverifiedRecipientPlaintext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecipientPlaintext {
    /// WalletUtxo.utxo.owner.
    pub owner_pubkey: PublicKey,
    /// WalletUtxo.utxo.asset.asset.
    pub mint: Address,
    /// WalletUtxo.utxo.amount.
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedRecipientPlaintext {
    /// Derives shared view tags with the sender.
    pub sender_pubkey: X25519Pubkey,
    /// WalletUtxo.utxo.blinding.
    pub blinding: [u8; 32],
    /// WalletUtxo.utxo.data.
    pub data: Data,
}

// Issue, AnonymousTransferSenderPlaintext encrypts 2 utxos thus ciphertexts will not map 1 to 1 to each utxo.
// Solution idea, leave sender utxos ciphertext empty and write AnonymousTransferSenderCiphertext into message

// How AnonymousTransferSenderPlaintext maps to WalletUtxo fields for sender SPL change (spl_amount > 0):
// 1. utxo.owner: PublicKey
//    verified.owner_pubkey
// 2. utxo.asset.asset: Address
//    verified.spl_mint
// 3. utxo.asset.asset_id: u64
//    AssetRegistry lookup by verified.spl_mint
// 4. utxo.amount: u64
//    verified.spl_amount
// 5. utxo.blinding: Blinding
//    derived from transaction's first nullifier, unverified.blinding_seed, and slot_index
// 6. utxo.ring_program_id: Option<Address>
//    indexed transaction's ring program, if SPL ring data is present
// 7. utxo.data: Data
//    unverified.spl_data
// 8. nullifier_pubkey: [u8; 32]
//    sender's shielded address
// 9. utxo_hash: [u8; 32]
//    indexed SPL output_context.hash, checked by reconstruction
// 10. nullifier: [u8; 32]
//     sender's nullifier key, utxo_hash, and utxo.blinding
// 11. tx_viewing_key: Option<[u8; 32]>
//     sender's viewing key and this UTXO's nullifier, for a future spend; initially None
// 12. data_hash: Option<[u8; 32]>
//     application-specific hash of unverified.spl_data.utxo_data(), or None
// 13. ring_data_hash: Option<[u8; 32]>
//     ring-specific hash of unverified.spl_data.ring_data(), or None
// 14. tree_id: u16
//     indexed SPL output_context.tree_id
// 15. leaf_index: u64
//     indexed SPL output_context.leaf_index
// 16. latest_tree_id: Option<u16>
//     indexer page's output_tree_id
// 17. slot: u64
//     indexed transaction's slot
// 18. tx_signature: Signature
//     indexed transaction's tx_signature
// 19. slot_index: u32
//     0; SPL change is the first output when present

// How AnonymousTransferSenderPlaintext maps to WalletUtxo fields for sender SOL change (sol_amount > 0):
// 1. utxo.owner: PublicKey
//    verified.owner_pubkey
// 2. utxo.asset.asset: Address
//    Mint::SOL.asset
// 3. utxo.asset.asset_id: u64
//    Mint::SOL.asset_id
// 4. utxo.amount: u64
//    verified.sol_amount
// 5. utxo.blinding: Blinding
//    derived from transaction's first nullifier, unverified.blinding_seed, and slot_index
// 6. utxo.ring_program_id: Option<Address>
//    indexed transaction's ring program, if SOL ring data is present
// 7. utxo.data: Data
//    unverified.sol_data
// 8. nullifier_pubkey: [u8; 32]
//    sender's shielded address
// 9. utxo_hash: [u8; 32]
//    indexed SOL output_context.hash, checked by reconstruction
// 10. nullifier: [u8; 32]
//     sender's nullifier key, utxo_hash, and utxo.blinding
// 11. tx_viewing_key: Option<[u8; 32]>
//     sender's viewing key and this UTXO's nullifier, for a future spend; initially None
// 12. data_hash: Option<[u8; 32]>
//     application-specific hash of unverified.sol_data.utxo_data(), or None
// 13. ring_data_hash: Option<[u8; 32]>
//     ring-specific hash of unverified.sol_data.ring_data(), or None
// 14. tree_id: u16
//     indexed SOL output_context.tree_id
// 15. leaf_index: u64
//     indexed SOL output_context.leaf_index
// 16. latest_tree_id: Option<u16>
//     indexer page's output_tree_id
// 17. slot: u64
//     indexed transaction's slot
// 18. tx_signature: Signature
//     indexed transaction's tx_signature
// 19. slot_index: u32
//     1 when verified.spl_amount > 0; otherwise 0

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferSenderPlaintext {
    /// Verifiably encrypted change fields and recipient viewing keys.
    pub verified: VerifiedSenderPlaintext,
    /// Encrypted without circuit enforcement.
    pub unverified: UnverifiedSenderPlaintext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSenderPlaintext {
    /// Each change WalletUtxo.utxo.owner.
    pub owner_pubkey: PublicKey,
    /// SPL change WalletUtxo.utxo.asset.asset.
    pub spl_mint: Address,
    /// SPL change WalletUtxo.utxo.amount; zero means absent.
    pub spl_amount: u64,
    /// SOL change WalletUtxo.utxo.amount; zero means absent.
    pub sol_amount: u64,
    /// Recipient encryption keys, bound to their output slots for auditor access.
    pub recipient_viewing_pks: Vec<X25519Pubkey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedSenderPlaintext {
    /// Derives each output's WalletUtxo.utxo.blinding.
    pub blinding_seed: [u8; 32],
    /// SPL change WalletUtxo.utxo.data.
    pub spl_data: Data,
    /// SOL change WalletUtxo.utxo.data.
    pub sol_data: Data,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditorUtxo {
    /// Circuit-enforced monitoring fields.
    pub verified: VerifiedAuditorData,
    /// Full unverified plaintext, or retained ciphertext.
    pub unverified: UnverifiedAuditorData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAuditorData {
    /// WalletUtxo.utxo.owner.
    pub owner: PublicKey,
    /// WalletUtxo.utxo.asset.asset.
    pub mint: Address,
    /// WalletUtxo.utxo.amount.
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnverifiedAuditorData {
    /// Readable by the auditor; contents remain unverified.
    Decrypted(UnverifiedAuditorPlaintext),
    /// Retained ciphertext when the auditor cannot decrypt it.
    Encrypted(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnverifiedAuditorPlaintext {
    /// Sender viewing key, output blinding, and recipient data.
    Recipient(UnverifiedRecipientPlaintext),
    /// Output blinding seed and both change outputs' data.
    Sender(UnverifiedSenderPlaintext),
}
