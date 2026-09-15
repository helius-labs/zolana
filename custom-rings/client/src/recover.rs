//! Rebuilds a source member's unspent ring notes from the auditor's visibility.

use std::{
    collections::{HashMap, HashSet},
    num::{NonZeroU32, NonZeroUsize},
};

use solana_address::Address;
use zolana_client::Rpc;
use zolana_keypair::{NullifierKey, ShieldedAddress, ViewingKey};
use zolana_ring_policy::Member;
use zolana_transaction::{AssetRegistry, OutputContext, Utxo, WalletUtxo};

use crate::{
    decrypt::TransactionAudit,
    error::{AuditError, RecoveryError},
    origin::TransactionOrigin,
    scan::{RingEnvironment, RingScan},
};

const DEFAULT_MAX_PAGES: NonZeroUsize = match NonZeroUsize::new(4096) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const DEFAULT_PAGE_SIZE: NonZeroU32 = match NonZeroU32::new(1000) {
    Some(value) => value,
    None => NonZeroU32::MIN,
};

#[must_use = "run the recovery explicitly"]
pub struct RingRecovery<'a> {
    ring_program_id: Address,
    auditor: &'a ViewingKey,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
}

pub struct SourceMember<'a> {
    pub address: &'a ShieldedAddress,
    pub nullifier_key: &'a NullifierKey,
}

#[must_use = "run the recovery explicitly"]
pub struct MemberRecovery<'a> {
    recovery: RingRecovery<'a>,
    source: SourceMember<'a>,
}

pub struct RecoveryEnvironment<'a, I, O, F> {
    pub ring: RingEnvironment<'a, I, O>,
    pub assets: &'a AssetRegistry,
    /// The raw id a note's leaf is committed under.
    pub tree_ids: F,
}

pub struct RecoveredNotes {
    pub utxos: Vec<WalletUtxo>,
    /// Commitments no rebuilt opening reproduces.
    pub unopened: Vec<[u8; 32]>,
}

impl<'a> RingRecovery<'a> {
    pub fn new(ring_program_id: Address, auditor: &'a ViewingKey) -> Self {
        Self {
            ring_program_id,
            auditor,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
        }
    }

    #[must_use = "use the updated recovery"]
    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    #[must_use = "use the updated recovery"]
    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    pub fn for_member(self, source: SourceMember<'a>) -> MemberRecovery<'a> {
        MemberRecovery {
            recovery: self,
            source,
        }
    }
}

impl SourceMember<'_> {
    fn verify(&self) -> Result<Member, RecoveryError> {
        if self.nullifier_key.pubkey()? != self.address.nullifier_pubkey {
            return Err(RecoveryError::NullifierKeyMismatch);
        }
        Ok(Member::owner_tag(&self.address.confidential_view_tag()?)?)
    }
}

struct Candidate {
    utxo: Utxo,
    output_context: OutputContext,
    nullifier: [u8; 32],
    tree_id: u16,
}

impl MemberRecovery<'_> {
    pub fn run<I, O, F>(
        self,
        env: RecoveryEnvironment<'_, I, O, F>,
    ) -> Result<RecoveredNotes, RecoveryError>
    where
        I: Rpc,
        O: TransactionOrigin,
        F: FnMut(Address) -> Result<u16, RecoveryError>,
    {
        let source_member = self.source.verify()?;
        let RecoveryEnvironment {
            ring,
            assets,
            mut tree_ids,
        } = env;
        let auditor_pk = self.recovery.auditor.pubkey();
        let page = RingScan::new(self.recovery.ring_program_id, &auditor_pk)
            .with_page_size(self.recovery.page_size)
            .with_max_pages(self.recovery.max_pages)
            .run(ring)?;
        if page.next_cursor.is_some() {
            return Err(RecoveryError::IncompleteScan);
        }

        let mut candidates = Vec::new();
        let mut unopened = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut known_tree_ids: HashMap<Address, u16> = HashMap::new();
        for transaction in &page.transactions {
            let audited = TransactionAudit {
                auditor: self.recovery.auditor,
                transaction,
                assets,
            }
            .run()?;
            for output in &audited.outputs {
                if output.recipient_viewing_pk != self.source.address.viewing_pubkey
                    || Member::owner_tag(&output.owner_tag)? != source_member
                {
                    continue;
                }
                let output_context = transaction
                    .output_slots
                    .get(output.slot_index as usize)
                    .map(|slot| slot.output_context.clone())
                    .ok_or(RecoveryError::MissingOutputSlot(output.slot_index))?;
                if !seen.insert(output_context.hash) {
                    continue;
                }
                let tree_id = match known_tree_ids.get(&output_context.tree) {
                    Some(id) => *id,
                    None => {
                        let id = tree_ids(output_context.tree)?;
                        known_tree_ids.insert(output_context.tree, id);
                        id
                    }
                };
                let utxo = Utxo {
                    owner: self.source.address.signing_pubkey,
                    asset: output.asset,
                    amount: output.amount,
                    blinding: *output.blinding,
                    ring_program_id: output.ring_program_id,
                    data: output.data.clone(),
                };
                // A hash match proves the rebuilt opening is the leaf on chain.
                let commitment = utxo.hash(
                    &self.source.address.nullifier_pubkey,
                    &[0u8; 32],
                    &[0u8; 32],
                    tree_id,
                )?;
                if commitment != output_context.hash {
                    unopened.push(output_context.hash);
                    continue;
                }
                let nullifier = utxo.nullifier(&output_context.hash, self.source.nullifier_key)?;
                candidates.push(Candidate {
                    utxo,
                    output_context,
                    nullifier,
                    tree_id,
                });
            }
        }
        let spent = spent_nullifiers(
            ring.indexer,
            candidates
                .iter()
                .map(|candidate| candidate.nullifier)
                .collect(),
        )?;
        let utxos = candidates
            .into_iter()
            .filter(|candidate| !spent.contains(&candidate.nullifier))
            .map(|candidate| WalletUtxo {
                utxo: candidate.utxo,
                output_context: candidate.output_context,
                nullifier: candidate.nullifier,
                data_hash: None,
                ring_data_hash: None,
                tree_id: candidate.tree_id,
                spent: false,
            })
            .collect();
        Ok(RecoveredNotes { utxos, unopened })
    }
}

/// A merge publishes no auditor message, only the indexer sees every spend.
fn spent_nullifiers<I: Rpc>(
    indexer: &I,
    nullifiers: Vec<[u8; 32]>,
) -> Result<HashSet<[u8; 32]>, RecoveryError> {
    let mut spent = HashSet::new();
    if nullifiers.is_empty() {
        return Ok(spent);
    }
    let mut cursor = None;
    loop {
        let page = indexer.get_shielded_transactions_by_nullifiers(
            nullifiers.clone(),
            cursor.clone(),
            None,
            None,
        )?;
        spent.extend(
            page.transactions
                .iter()
                .flat_map(|transaction| transaction.nullifiers.iter().copied()),
        );
        // A terminal page still names a cursor, only `scanned_through` ends the scan.
        if page.scanned_through.is_some() {
            return Ok(spent);
        }
        let Some(next) = page.next_cursor else {
            return Ok(spent);
        };
        if cursor.as_ref() == Some(&next) {
            return Err(AuditError::CursorNotAdvanced.into());
        }
        cursor = Some(next);
    }
}
