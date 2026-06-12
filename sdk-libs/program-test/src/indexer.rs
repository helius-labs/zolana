//! Test-side indexer for the shielded pool.
//!
//! A real indexer reads `ProoflessShieldEvent`s from `emit_event` inner
//! instructions (self-CPIs by the shielded-pool program) and tracks where
//! each deposit landed in the state tree. This replays the same events into
//! an in-memory reference tree, so tests can
//! - assert the on-chain state root matches an independent recomputation, and
//! - locate a deposited UTXO (leaf index + fields) the way a wallet would,
//!   without any decryption.

use light_hasher::{Hasher, Poseidon};
use light_sparse_merkle_tree::SparseMerkleTree;
use shielded_pool_program::instructions::create_tree::init::STATE_HEIGHT;
use zolana_interface::instruction::ProoflessShieldEvent;

/// Domain separator for UTXO commitments (spec: UTXO Hash). Must match the
/// program and the circuit (`protocol.UtxoDomain`).
const UTXO_DOMAIN: u64 = 1;

/// One deposited UTXO as an indexer sees it: the event fields plus its
/// position in the state tree.
#[derive(Clone, Debug)]
pub struct UtxoRecord {
    pub utxo_hash: [u8; 32],
    pub owner_utxo_hash: [u8; 32],
    /// Mint address; all-zero for SOL.
    pub asset: [u8; 32],
    pub amount: u64,
    pub view_tag: [u8; 32],
    /// Blinding-derivation salt (spec: Blinding derivation).
    pub salt: [u8; 16],
    pub leaf_index: u64,
}

pub struct PoolIndexer {
    tree: SparseMerkleTree<Poseidon, STATE_HEIGHT>,
    utxos: Vec<UtxoRecord>,
}

impl Default for PoolIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolIndexer {
    pub fn new() -> Self {
        Self {
            tree: SparseMerkleTree::new_empty(),
            utxos: Vec::new(),
        }
    }

    /// Record a `ProoflessShieldEvent`: verify the emitted UTXO hash against
    /// an independent recomputation, append it to the reference tree, and
    /// remember where it landed. Returns the record.
    pub fn record_proofless_shield(&mut self, event: &ProoflessShieldEvent) -> &UtxoRecord {
        let recomputed = utxo_hash(event);
        assert_eq!(
            recomputed, event.utxo_hash,
            "event utxo_hash must match recomputation from event fields"
        );

        let leaf_index = self.tree.get_next_index() as u64;
        self.tree.append(event.utxo_hash);
        self.utxos.push(UtxoRecord {
            utxo_hash: event.utxo_hash,
            owner_utxo_hash: event.owner_utxo_hash,
            asset: event.asset,
            amount: event.amount,
            view_tag: event.view_tag,
            salt: event.salt,
            leaf_index,
        });
        self.utxos.last().expect("just pushed")
    }

    /// Root of the reference state tree. Tests assert this equals the
    /// on-chain root (`PoolTestRig::state_root`).
    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Locate a deposit the way the depositor would: by the opaque
    /// `owner_utxo_hash` they committed to.
    pub fn fetch_by_owner_utxo_hash(&self, owner_utxo_hash: &[u8; 32]) -> Option<&UtxoRecord> {
        self.utxos
            .iter()
            .find(|u| &u.owner_utxo_hash == owner_utxo_hash)
    }

    /// Locate deposits the way a recipient would: by scanning for their view
    /// tag.
    pub fn fetch_by_view_tag<'a>(
        &'a self,
        tag: &'a [u8; 32],
    ) -> impl Iterator<Item = &'a UtxoRecord> + 'a {
        self.utxos.iter().filter(move |u| &u.view_tag == tag)
    }

    pub fn utxos(&self) -> &[UtxoRecord] {
        &self.utxos
    }
}

/// Recompute the UTXO commitment from event fields, mirroring the program.
fn utxo_hash(event: &ProoflessShieldEvent) -> [u8; 32] {
    // zone_program_id is a raw pubkey in the event; the UTXO hash uses its
    // pk_field encoding (spec: UTXO Hash), matching the program.
    let zone_program_id = match event.zone_program_id {
        Some(program_id) => pk_field_solana(&program_id),
        None => [0u8; 32],
    };
    let policy_data_hash = event.policy_data_hash.unwrap_or([0u8; 32]);
    let program_data_hash = event.program_data_hash.unwrap_or([0u8; 32]);
    Poseidon::hashv(&[
        field_from_u64(UTXO_DOMAIN).as_slice(),
        pk_field_solana(&event.asset).as_slice(),
        field_from_u64(event.amount).as_slice(),
        program_data_hash.as_slice(),
        policy_data_hash.as_slice(),
        zone_program_id.as_slice(),
        event.owner_utxo_hash.as_slice(),
    ])
    .expect("poseidon")
}

/// Encodes a u64 as a big-endian field element (value in the low 8 bytes).
fn field_from_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

/// `pk_field` of a Solana / Ed25519 pubkey (spec: Shielded Address):
/// Poseidon over the two 128-bit big-endian limbs.
fn pk_field_solana(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut low = [0u8; 32];
    low[16..32].copy_from_slice(&pubkey[16..]);
    let mut high = [0u8; 32];
    high[16..32].copy_from_slice(&pubkey[..16]);
    Poseidon::hashv(&[low.as_slice(), high.as_slice()]).expect("poseidon")
}
