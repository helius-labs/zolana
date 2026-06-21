//! The cucumber `World`: localnet/indexer handles, per-actor state, and setup.
//!
//! The lifecycle operations live next to their cucumber steps in `steps/*`, each
//! adding an `impl LifecycleWorld` block; the fields and actor accessors here are
//! `pub(crate)` so those step modules can drive the World.

use std::collections::BTreeMap;

use anyhow::Result;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{SolanaRpc, ZolanaIndexer};
use zolana_interface::{
    instruction::CreateProtocolConfig, state::tree_account_size, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::create_tree_instructions;
use zolana_transaction::{AssetRegistry, SyncTransaction};

use crate::{
    actor::Actor,
    localnet::{
        restart_localnet, send_transaction, start_prover, DEFAULT_INDEXER_URL, DEFAULT_RPC_URL,
    },
};

/// The single SPL asset a scenario registers: its mint, the vault the deposit
/// credits, and the shared funding token account (owned by the payer).
pub(crate) struct SplAsset {
    pub(crate) mint: Pubkey,
    pub(crate) vault: Pubkey,
    pub(crate) user_token: Pubkey,
}

/// Which ownership rail the last transfer took. P256 proves ownership inside the
/// proof; Eddsa proves it with an ed25519 signature on the transaction, checked by
/// the program against the eddsa signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rail {
    P256,
    Eddsa,
}

#[derive(cucumber::World)]
#[world(init = Self::new)]
pub struct LifecycleWorld {
    pub(crate) rpc: SolanaRpc,
    pub(crate) indexer: ZolanaIndexer,
    pub(crate) assets: AssetRegistry,
    pub(crate) payer: Keypair,
    pub(crate) authority: Keypair,
    pub(crate) tree: Pubkey,
    pub(crate) tree_address: Address,
    pub(crate) actors: BTreeMap<String, Actor>,
    /// The Solana keypair each actor registered on the user-registry under, kept so
    /// the merge step can derive the `user_record` PDA the program reads.
    pub(crate) merge_owners: BTreeMap<String, Keypair>,
    pub(crate) indexed: Vec<SyncTransaction>,
    pub(crate) spl: Option<SplAsset>,
    pub(crate) last_rail: Option<Rail>,
    /// The most recent `transact` instruction and its transaction signature, kept
    /// so the decode step can re-parse the exact bytes and accounts that were sent.
    pub(crate) last_transact: Option<(Signature, Instruction)>,
    /// The most recent merge, kept so the consolidated-output assert can reconstruct
    /// and verify the merged UTXO.
    pub(crate) last_merge: Option<crate::steps::merge::MergeRecord>,
}

impl std::fmt::Debug for LifecycleWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LifecycleWorld")
    }
}

impl LifecycleWorld {
    async fn new() -> Result<Self> {
        // The prover is independent of the validator and indexer, so start it
        // concurrently with the validator + Photon restart and join before use.
        let prover = std::thread::spawn(start_prover);
        restart_localnet();
        prover.join().expect("prover startup thread panicked")?;

        let rpc_url =
            std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
        let indexer_url =
            std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
        let mut rpc = SolanaRpc::new(rpc_url);
        let indexer = ZolanaIndexer::new(indexer_url);
        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        rpc.assert_executable(&program_id)?;

        let payer = Keypair::new();
        let authority = Keypair::new();
        rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
        rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;

        let authority_bytes = authority.pubkey().to_bytes();
        let create_config = CreateProtocolConfig {
            authority: authority.pubkey(),
            protocol_authority: authority_bytes.into(),
            tree_creation_authority: authority_bytes.into(),
            tree_creation_is_permissionless: false,
            forester_authority: authority_bytes.into(),
            zone_creation_authority: authority_bytes.into(),
            zone_creation_is_permissionless: false,
            merge_authority: authority_bytes.into(),
        }
        .instruction();
        send_transaction(
            &mut rpc,
            &[create_config],
            &authority.pubkey(),
            &[&authority],
        )?;

        let tree = Keypair::new();
        let create_tree = create_tree_instructions(
            &rpc,
            &payer.pubkey(),
            &authority.pubkey(),
            &tree.pubkey(),
            tree_account_size() as u64,
        )?;
        send_transaction(
            &mut rpc,
            &create_tree,
            &payer.pubkey(),
            &[&payer, &tree, &authority],
        )?;

        let tree_address = Address::new_from_array(tree.pubkey().to_bytes());
        Ok(Self {
            rpc,
            indexer,
            assets: AssetRegistry::default(),
            payer,
            authority,
            tree: tree.pubkey(),
            tree_address,
            actors: BTreeMap::new(),
            merge_owners: BTreeMap::new(),
            indexed: Vec::new(),
            spl: None,
            last_rail: None,
            last_transact: None,
            last_merge: None,
        })
    }

    pub(crate) fn ensure_actor(&mut self, name: &str) -> Result<()> {
        if !self.actors.contains_key(name) {
            self.actors.insert(name.to_string(), Actor::new()?);
        }
        Ok(())
    }

    pub(crate) fn actor(&self, name: &str) -> &Actor {
        self.actors.get(name).expect("actor exists")
    }

    pub(crate) fn actor_mut(&mut self, name: &str) -> &mut Actor {
        self.actors.get_mut(name).expect("actor exists")
    }
}
