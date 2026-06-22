use std::collections::HashMap;
use std::thread::sleep;
use std::time::{Duration, SystemTime};

use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::instruction::MergeTransact;
use zolana_interface::pda;
use zolana_keypair::SignatureType;
use zolana_transaction::{AssetRegistry, Wallet};
use zolana_user_registry_interface::instruction::{
    set_merge_service, set_sync_delegate, SetSyncDelegateData,
};
use zolana_user_registry_interface::user_record_pda;

use crate::error::ClientError;
use crate::private_transaction::{
    Merge, MergeOwner, PreparedMerge, SpendProof, SpendUtxo, MERGE_INPUTS,
};
use crate::prover::{ProofCompressed, ProverClient};
use crate::rpc::Rpc;
use crate::user_registry::fetch_user_record_checked;
use crate::wallet_authority::WalletAuthority;
use crate::wallet_sync::{sync_wallet_with_config, SyncWalletConfig};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_INDEXER_POLL: Duration = Duration::from_millis(500);
const DEFAULT_MAX_MERGES_PER_RUN: usize = 1;
const DEFAULT_MIN_INPUTS_PER_MERGE: usize = 2;
const DEFAULT_PRE_ACTION_ROUNDS: usize = 8;

#[derive(Clone, Debug)]
pub struct MergeServiceConfig {
    pub sync: SyncWalletConfig,
    pub poll_interval: Duration,
    pub indexer_timeout: Duration,
    pub indexer_poll_interval: Duration,
    pub max_merges_per_run: usize,
    pub min_inputs_per_merge: usize,
    pub auto_enable_registry: bool,
}

impl Default for MergeServiceConfig {
    fn default() -> Self {
        Self {
            sync: SyncWalletConfig::default(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            indexer_timeout: DEFAULT_INDEXER_TIMEOUT,
            indexer_poll_interval: DEFAULT_INDEXER_POLL,
            max_merges_per_run: DEFAULT_MAX_MERGES_PER_RUN,
            min_inputs_per_merge: DEFAULT_MIN_INPUTS_PER_MERGE,
            auto_enable_registry: true,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MergeServiceReport {
    pub sync: zolana_transaction::SyncReport,
    pub submitted: Vec<Signature>,
}

impl MergeServiceReport {
    pub fn is_idle(&self) -> bool {
        self.submitted.is_empty()
    }
}

pub struct LocalMergeService<'a, C, I, A>
where
    C: Rpc,
    I: Rpc,
    A: WalletAuthority,
{
    pub chain: &'a C,
    pub indexer: &'a I,
    pub wallet: &'a mut Wallet,
    pub authority: &'a A,
    pub owner_pubkey: Pubkey,
    pub payer: &'a Keypair,
    pub tree: Pubkey,
    pub assets: &'a AssetRegistry,
    pub prover: ProverClient,
    pub config: MergeServiceConfig,
}

impl<C, I, A> LocalMergeService<'_, C, I, A>
where
    C: Rpc,
    I: Rpc,
    A: WalletAuthority,
{
    pub fn run(&mut self) -> Result<(), ClientError> {
        if self.config.auto_enable_registry {
            self.ensure_self_delegated()?;
        }
        loop {
            self.run_once()?;
            sleep(self.config.poll_interval);
        }
    }

    pub fn run_once(&mut self) -> Result<MergeServiceReport, ClientError> {
        if self.config.auto_enable_registry {
            self.ensure_self_delegated()?;
        }

        let mut report = MergeServiceReport {
            sync: self.sync_wallet()?,
            submitted: Vec::new(),
        };
        let max_merges = self.config.max_merges_per_run.max(1);
        for _ in 0..max_merges {
            let Some(inputs) = self.next_merge_inputs()? else {
                break;
            };
            let signature = self.submit_merge(inputs)?;
            self.wait_for_indexed_merge(signature)?;
            report.submitted.push(signature);
            report.sync = self.sync_wallet()?;
        }
        Ok(report)
    }

    pub fn run_until_idle(&mut self, max_rounds: usize) -> Result<MergeServiceReport, ClientError> {
        let rounds = max_rounds.max(1);
        let mut combined = MergeServiceReport::default();
        for _ in 0..rounds {
            let report = self.run_once()?;
            let idle = report.is_idle();
            combined.sync = report.sync.clone();
            combined.submitted.extend(report.submitted);
            if idle {
                break;
            }
        }
        Ok(combined)
    }

    pub fn run_pre_action(&mut self) -> Result<MergeServiceReport, ClientError> {
        self.run_until_idle(DEFAULT_PRE_ACTION_ROUNDS)
    }

    pub fn ensure_self_delegated(&self) -> Result<Option<Signature>, ClientError> {
        let owner = self.payer.pubkey();
        let address = self.authority.shielded_address(self.owner_pubkey)?;
        let record = fetch_user_record_checked(self.chain, owner)?;
        let expected_owner_p256 = match address.signing_pubkey.signature_type()? {
            SignatureType::P256 => Some(*address.signing_pubkey.as_p256()?.as_bytes()),
            SignatureType::Ed25519 => None,
        };
        if record.owner_p256 != expected_owner_p256
            || record.nullifier_pubkey != address.nullifier_pubkey
            || record.viewing_pubkey != *address.viewing_pubkey.as_bytes()
        {
            return Err(ClientError::AddressResolution(format!(
                "user registry record for {owner} does not match the merge authority"
            )));
        }
        let desired_viewing = *address.viewing_pubkey.as_bytes();
        let self_delegate = owner.to_bytes();
        let delegate_ok = record.sync_delegate == Some(self_delegate)
            && record.entries.last().is_some_and(|entry| {
                entry.delegate == self_delegate
                    && entry.sync_pubkey == desired_viewing
                    && entry.viewing_pubkey == desired_viewing
            });
        let merge_ok = record.merge_service;
        if delegate_ok && merge_ok {
            return Ok(None);
        }

        let (user_record, _bump) = user_record_pda(&owner);
        let mut instructions = Vec::new();
        if !delegate_ok {
            instructions.push(set_sync_delegate(
                user_record,
                owner,
                SetSyncDelegateData {
                    sync_delegate: self_delegate,
                    sync_pubkey: desired_viewing,
                    viewing_pubkey: desired_viewing,
                },
            ));
        }
        if !merge_ok {
            instructions.push(set_merge_service(user_record, owner, true));
        }

        self.chain
            .create_and_send_transaction(
                &instructions,
                Address::new_from_array(owner.to_bytes()),
                &[self.payer],
            )
            .map(Some)
    }

    fn sync_wallet(&mut self) -> Result<zolana_transaction::SyncReport, ClientError> {
        let mut config = self.config.sync;
        config.merge_owner_tag = Some(merge_owner_tag(self.payer.pubkey()));
        sync_wallet_with_config(self.wallet, self.indexer, self.assets, config)
    }

    fn next_merge_inputs(&self) -> Result<Option<Vec<SpendUtxo>>, ClientError> {
        let min_inputs = self.config.min_inputs_per_merge.max(2).min(MERGE_INPUTS);
        let nullifier_key = self.authority.spend_nullifier_key(self.owner_pubkey)?;
        let mut by_asset: HashMap<Address, Vec<&zolana_transaction::WalletUtxo>> = HashMap::new();
        for entry in &self.wallet.utxos {
            if entry.spent
                || entry.utxo.amount == 0
                || entry.utxo.zone_program_id.is_some()
                || !entry.utxo.data.is_empty()
            {
                continue;
            }
            by_asset.entry(entry.utxo.asset).or_default().push(entry);
        }

        let Some(mut candidates) = by_asset
            .into_values()
            .filter(|entries| entries.len() >= min_inputs)
            .max_by_key(|entries| entries.len())
        else {
            return Ok(None);
        };
        candidates.sort_by_key(|entry| (entry.utxo.amount, entry.hash));
        candidates.truncate(MERGE_INPUTS);
        candidates
            .into_iter()
            .map(|entry| {
                Ok(SpendUtxo {
                    utxo: entry.utxo.clone(),
                    nullifier_key: nullifier_key.clone(),
                    zone_data_hash: None,
                    program_data_hash: None,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    fn submit_merge(&self, inputs: Vec<SpendUtxo>) -> Result<Signature, ClientError> {
        let address = self.authority.shielded_address(self.owner_pubkey)?;
        let first = inputs.first().ok_or(ClientError::NoInputs)?;
        let owner = MergeOwner {
            signing_pubkey: address.signing_pubkey,
            nullifier_pubkey: first.nullifier_key.pubkey()?,
            nullifier_secret: *first.nullifier_key.secret(),
            viewing_pubkey: address.viewing_pubkey,
        };
        let merge = Merge::new_with_owner(owner, inputs)?;
        let prepared = PreparedMerge::from(merge);
        let commitments = prepared.input_commitments()?;
        let proofs = spend_proofs(self.indexer, self.tree, &commitments)?;
        let result = prepared.into_prover(&proofs)?.build()?;
        let proof = self.prover.prove_merge(&result.inputs)?;
        let proof_bytes = ProofCompressed::try_from(proof)?.to_transact_proof_bytes();
        let owner = self.payer.pubkey();
        let (user_record, _bump) = user_record_pda(&owner);
        let ix = MergeTransact {
            tree: self.tree,
            protocol_config: pda::protocol_config(),
            payer: owner,
            user_record,
            data: result.instruction_data(proof_bytes),
        }
        .instruction();
        let instructions = [
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
                1_400_000,
            ),
            ix,
        ];
        self.chain.create_and_send_transaction(
            &instructions,
            Address::new_from_array(owner.to_bytes()),
            &[self.payer],
        )
    }

    fn wait_for_indexed_merge(&self, signature: Signature) -> Result<(), ClientError> {
        let started = SystemTime::now();
        let tag = merge_owner_tag(self.payer.pubkey());
        loop {
            let response =
                self.indexer
                    .get_shielded_transactions_by_tags(vec![tag], None, Some(50))?;
            if response
                .transactions
                .iter()
                .any(|tx| tx.tx_signature == signature)
            {
                return Ok(());
            }
            if started.elapsed().unwrap_or_default() >= self.config.indexer_timeout {
                return Err(ClientError::Rpc(format!(
                    "timed out waiting for indexer to return merge transaction {signature}"
                )));
            }
            sleep(self.config.indexer_poll_interval);
        }
    }
}

fn spend_proofs<R: Rpc>(
    indexer: &R,
    tree: Pubkey,
    commitments: &[crate::private_transaction::InputCommitment],
) -> Result<Vec<SpendProof>, ClientError> {
    let tree_address = Address::new_from_array(tree.to_bytes());
    let leaves = commitments
        .iter()
        .map(|commitment| commitment.utxo_hash)
        .collect::<Vec<_>>();
    let nullifiers = commitments
        .iter()
        .map(|commitment| commitment.nullifier)
        .collect::<Vec<_>>();
    let state_proofs = indexer.get_merkle_proofs(tree_address, leaves)?.proofs;
    let nullifier_proofs = indexer
        .get_non_inclusion_proofs(tree_address, nullifiers)?
        .proofs;
    if state_proofs.len() != commitments.len() || nullifier_proofs.len() != commitments.len() {
        return Err(ClientError::Rpc(
            "indexer returned incomplete merge input proofs".into(),
        ));
    }
    Ok(state_proofs
        .into_iter()
        .zip(nullifier_proofs)
        .map(|(state, nullifier)| SpendProof { state, nullifier })
        .collect())
}

pub fn merge_owner_tag(owner: Pubkey) -> [u8; 32] {
    owner.to_bytes()
}
