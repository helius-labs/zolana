//! Localnet/indexer handles, per-actor state, and lifecycle setup.
//!
//! The validator/prover/indexer bring-up, actor management, and SPL asset
//! registration are shared with the zone suite in
//! `zolana_test_utils::harness::LocalnetHarness`; this struct embeds it and adds
//! the merge-specific state only the plain-pool lifecycle needs.

use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use anyhow::Result;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signature::Signature;
use zolana_interface::instruction::AssetDeposit;
use zolana_test_utils::harness::{BootstrapConfig, LocalnetHarness};

/// Which ownership rail the last transfer took. P256 proves ownership inside the
/// proof; Eddsa proves it with an ed25519 signature on the transaction, checked by
/// the program against the eddsa signer. The P256 rail is removed; the variant is
/// kept so rail assertions document what a spend must NOT take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Rail {
    P256,
    Eddsa,
}

pub struct LifecycleHarness {
    pub(crate) base: LocalnetHarness<AssetDeposit>,
    /// The Solana keypair each actor registered on the user-registry under, kept so
    /// the merge step can derive the `user_record` PDA the program reads.
    pub(crate) merge_owners: BTreeMap<String, Keypair>,
    pub(crate) last_rail: Option<Rail>,
    /// The most recent `transact` instruction and its transaction signature, kept
    /// so the decode step can re-parse the exact bytes and accounts that were sent.
    pub(crate) last_transact: Option<(Signature, Instruction)>,
    /// The most recent merge, kept so the consolidated-output assert can reconstruct
    /// and verify the merged UTXO.
    pub(crate) last_merge: Option<crate::actions::merge::MergeRecord>,
    pub(crate) merge_key: Keypair,
}

impl std::fmt::Debug for LifecycleHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LifecycleHarness")
    }
}

impl Deref for LifecycleHarness {
    type Target = LocalnetHarness<AssetDeposit>;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for LifecycleHarness {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl LifecycleHarness {
    pub(crate) fn new() -> Result<Self> {
        let (base, keys) = LocalnetHarness::bootstrap(BootstrapConfig {
            label: "zolana-spp",
            extra_programs: Vec::new(),
            zone_creation_is_permissionless: false,
            fund_merge_vault: true,
        })?;
        Ok(Self {
            base,
            merge_owners: BTreeMap::new(),
            last_rail: None,
            last_transact: None,
            last_merge: None,
            merge_key: keys.merge_key,
        })
    }
}
