//! Autonomous background settlement crank.
//!
//! [`SquadsBackend::new_with_crank`] spawns one thread that polls the zone program's
//! `Proposal` PDAs, reconstructs and verifies each against on-chain data plus the
//! auditor key ([`SquadsBackend::reconstruct_zone_proposal`]), gathers the sender's
//! spendable UTXOs, proves the smart-account (signatureless) settlement, and sends
//! `execute_proposal` over a v0 transaction backed by a freshly built address
//! lookup table. It settles both transfers and withdrawals on the smart-account
//! rail; the prior proposal approval authorizes the spend, so only the relayer /
//! co-signer key signs (CT's model).
//!
//! `Rpc` is not `Send + 'static` and `SolanaRpc` is not `Clone`, so the thread
//! builds its own `ZolanaIndexer` / `SolanaRpc` from the endpoint URLs and a fresh
//! crankless backend ([`SquadsBackend::new`]) from the auditor secret,
//! relayer key, and asset map cloned out of the parent. Settled proposals are
//! tracked in a thread-local set; only a shutdown flag is shared, and [`Drop`]
//! signals it and joins the thread.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use p256::{
    elliptic_curve::rand_core::{OsRng, RngCore},
    SecretKey,
};
use solana_account::Account;
use solana_address_lookup_table_interface::{
    instruction::{create_lookup_table, extend_lookup_table},
    state::AddressLookupTable,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::AddressLookupTableAccount;
use solana_pubkey::Pubkey;
use zolana_client::{Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::{
    instruction::instruction_data::merge_transact::MERGE_INPUT_COUNT, pda, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{hash::hash_field, NullifierKey};
use zolana_squads_interface::{
    error::SquadsZoneError,
    instruction::{
        builders::{ExecuteProposal, MergeTransact, TransactWithdrawal},
        instruction_data::{
            EncryptedUtxos, ExecuteProposalIxData, InputContext, MergeTransactIxData,
        },
    },
    state::{Proposal, ViewingKeyAccount},
    SQUADS_ZONE_PROGRAM_ID,
};
use zolana_squads_sdk::prover::{
    prove_squads_merge, prove_squads_smart_account_transfer, prove_squads_smart_account_withdrawal,
    SquadsMergeInput, SquadsMergeRequest, SquadsSmartAccountIdentity,
    SquadsSmartAccountTransferRequest, SquadsSmartAccountWithdrawalRequest, SquadsTransferInput,
    SquadsWithdrawalInput,
};
use zolana_transaction::Address;

use crate::{
    backend::{SquadsBackend, SOL_ASSET_ID},
    error::{Result, SquadsBackendError},
    proposals::{OP_TRANSFER, OP_WITHDRAW},
    tags::{account_view_tag, view_tag_from_shared_viewing_key},
    types::{GetBalancesRequest, ReconstructedProposal},
};

/// Poll cadence for the crank loop.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Timeout waiting for a freshly created lookup table to activate.
const ALT_ACTIVATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Validity window stamped on auto-merge proofs (SPP `merge_zone` enforces it
/// against the chain clock). A merge binds no proposal, so the crank sets its own
/// deadline off the local clock rather than echoing a proposal `expiry`.
const MERGE_EXPIRY_WINDOW_SECS: u64 = 600;
/// Backoff before retrying an owner whose merge failed with the permanent
/// `MergeAuthorityNotWhitelisted` config error (the crank relayer is not yet a
/// whitelisted merge authority); retrying sooner cannot succeed.
const MERGE_BACKOFF_PERMANENT: Duration = Duration::from_secs(60);
/// Backoff before retrying an owner whose merge failed for any other (likely
/// transient) reason.
const MERGE_BACKOFF_TRANSIENT: Duration = Duration::from_secs(2);

fn to_pubkey(address: Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

/// Current wall-clock unix time in seconds; `0` if the clock is before the epoch.
fn current_unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a merge send failure is the permanent `MergeAuthorityNotWhitelisted`
/// zone config error (a `ProgramError::Custom(8021)`), which surfaces in the send
/// error string as the hex custom-error code (`custom program error: 0x1f55`).
/// Any other error is treated as transient. Detection is best-effort string
/// matching on the code the runtime renders; a false negative only shortens the
/// backoff (the next tick retries), never causing an unsafe spend.
fn is_merge_authority_not_whitelisted(err: &SquadsBackendError) -> bool {
    let code = SquadsZoneError::MergeAuthorityNotWhitelisted as u32;
    let hex = format!("0x{code:x}");
    err.to_string().to_ascii_lowercase().contains(&hex)
}

/// Decoded `Proposal` PDAs keyed by address, from one program-account scan.
type ProposalScan = Vec<(Address, Proposal)>;
/// Decoded `ViewingKeyAccount` PDAs keyed by address, from one program-account scan.
type ViewingKeyAccountScan = Vec<(Address, ViewingKeyAccount)>;

/// Split one zone program-account scan into `Proposal` and `ViewingKeyAccount`
/// PDAs by their leading discriminator byte, decoding each into its typed form.
/// Accounts of any other kind (or that fail to decode) are dropped.
fn partition_zone_accounts(
    accounts: Vec<(Address, Account)>,
) -> (ProposalScan, ViewingKeyAccountScan) {
    let mut proposals = Vec::new();
    let mut viewing_key_accounts = Vec::new();
    for (address, account) in accounts {
        match account.data.first().copied() {
            Some(Proposal::DISCRIMINATOR) => {
                if let Ok(proposal) = Proposal::deserialize(&account.data) {
                    proposals.push((address, proposal));
                }
            }
            Some(ViewingKeyAccount::DISCRIMINATOR) => {
                if let Ok(vka) = ViewingKeyAccount::deserialize(&account.data) {
                    viewing_key_accounts.push((address, vka));
                }
            }
            _ => {}
        }
    }
    (proposals, viewing_key_accounts)
}

/// The owner fields with an OPEN proposal this scan: a `Proposal` PDA present that
/// the crank has neither settled nor permanently skipped. Merging one of these
/// owners could double-spend inputs a pending settlement will consume.
fn open_proposal_owners(
    proposals: &[(Address, Proposal)],
    settled: &HashSet<[u8; 32]>,
    skipped: &HashSet<[u8; 32]>,
) -> HashSet<[u8; 32]> {
    proposals
        .iter()
        .filter(|(pda, _)| {
            let key = pda.to_bytes();
            !settled.contains(&key) && !skipped.contains(&key)
        })
        .map(|(_, proposal)| proposal.owner.to_bytes())
        .collect()
}

fn random_blinding() -> [u8; 31] {
    let mut b = [0u8; 31];
    OsRng.fill_bytes(&mut b);
    b
}

fn random_salt() -> [u8; 16] {
    let mut s = [0u8; 16];
    OsRng.fill_bytes(&mut s);
    s
}

/// Handle to the background crank thread; dropping the backend stops and joins it.
pub(crate) struct CrankHandle {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl CrankHandle {
    /// Signal the loop to stop and join the thread.
    pub(crate) fn stop(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl SquadsBackend<ZolanaIndexer, SolanaRpc> {
    /// Construct the backend from endpoint URLs and start the background
    /// settlement crank. The crank polls the zone program's `Proposal` PDAs,
    /// decrypts them with the auditor key, and settles them with the relayer;
    /// dropping the backend stops it. Crankless construction from pre-built
    /// indexer/RPC instances goes through [`SquadsBackend::new`].
    pub fn new_with_crank(
        auditor_sk: SecretKey,
        zone_authority: Keypair,
        zone_config: Address,
        tree: Address,
        prover_url: impl Into<String>,
        indexer_url: impl Into<String>,
        rpc_url: impl Into<String>,
    ) -> Self {
        let indexer_url = indexer_url.into();
        let rpc_url = rpc_url.into();
        Self::new(
            auditor_sk,
            zone_authority,
            zone_config,
            tree,
            prover_url,
            ZolanaIndexer::new(&indexer_url),
            SolanaRpc::new(rpc_url.clone()),
        )
        .with_crank(indexer_url, rpc_url)
    }
}

impl<I: Rpc, R: Rpc> SquadsBackend<I, R> {
    /// Spawn the background settlement crank. The thread builds its own concrete
    /// `ZolanaIndexer` / `SolanaRpc` from the endpoint URLs (the parent's handles
    /// are neither `Send` nor `Clone`) and a fresh backend from the auditor secret,
    /// relayer key, and asset map, then polls and settles proposals until dropped.
    pub(crate) fn with_crank(
        mut self,
        indexer_url: impl Into<String>,
        rpc_url: impl Into<String>,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);

        let auditor = self.auditor_secret().clone();
        let zone_authority = self.zone_authority().insecure_clone();
        let zone_config = self.zone_config();
        let tree = self.tree();
        let prover_url = self.prover_url().to_string();
        let assets: Vec<(u64, Address)> = self.assets().to_vec();
        let indexer_url = indexer_url.into();
        let rpc_url = rpc_url.into();

        let handle = thread::spawn(move || {
            let indexer = ZolanaIndexer::new(&indexer_url);
            let rpc = SolanaRpc::new(rpc_url);
            let mut backend = SquadsBackend::new(
                auditor,
                zone_authority,
                zone_config,
                tree,
                prover_url,
                indexer,
                rpc,
            );
            for (asset_id, mint) in assets {
                backend.register_asset(asset_id, mint);
            }
            backend.run_crank_loop(&thread_shutdown);
        });

        self.set_crank(CrankHandle {
            shutdown,
            handle: Some(handle),
        });
        self
    }

    /// The crank poll loop: settle every unsettled proposal, then sleep. Errors are
    /// swallowed so a single bad tick does not kill the thread; permanently invalid
    /// proposals (unsupported / hash-mismatch) are skipped, transient failures are
    /// retried next tick.
    fn run_crank_loop(&self, shutdown: &AtomicBool) {
        let mut settled: HashSet<[u8; 32]> = HashSet::new();
        let mut skipped: HashSet<[u8; 32]> = HashSet::new();
        // Input utxo hashes of merges just sent; bridges indexer lag so the next
        // tick does not re-merge the same inputs before photon reflects the spend.
        let mut inflight_spent: HashSet<[u8; 32]> = HashSet::new();
        // Per-owner-field retry deadline after a merge send failure.
        let mut merge_backoff: HashMap<[u8; 32], Instant> = HashMap::new();
        while !shutdown.load(Ordering::SeqCst) {
            let _ = self.crank_tick(
                &mut settled,
                &mut skipped,
                &mut inflight_spent,
                &mut merge_backoff,
            );
            // Sleep in short slices so shutdown is observed promptly.
            let started = Instant::now();
            while started.elapsed() < POLL_INTERVAL {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn crank_tick(
        &self,
        settled: &mut HashSet<[u8; 32]>,
        skipped: &mut HashSet<[u8; 32]>,
        inflight_spent: &mut HashSet<[u8; 32]>,
        merge_backoff: &mut HashMap<[u8; 32], Instant>,
    ) -> Result<()> {
        let program_id = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);
        let (proposals, viewing_key_accounts) =
            partition_zone_accounts(self.rpc().get_program_accounts(program_id)?);

        // 1. Settle every pending proposal first.
        for (pda, proposal) in &proposals {
            let key = pda.to_bytes();
            if settled.contains(&key) || skipped.contains(&key) {
                continue;
            }
            match self.settle_proposal(*pda, proposal) {
                Ok(()) => {
                    settled.insert(key);
                }
                // Unsupported / hash-mismatch is permanent; do not retry forever.
                Err(SquadsBackendError::Unsupported(_)) => {
                    skipped.insert(key);
                }
                // Transient (proof server warmup, missing indexer proof, send
                // failure): leave unsettled to retry next tick.
                Err(_) => {}
            }
        }

        // 2. Owners with an open proposal are skipped for merging this tick: a
        // settlement will spend their inputs.
        let open_owners = open_proposal_owners(&proposals, settled, skipped);
        let now = Instant::now();
        merge_backoff.retain(|_, deadline| *deadline > now);

        // 3. Auto-merge every other owner's fragmented balances.
        for (vka_address, vka) in &viewing_key_accounts {
            let owner_key = vka.owner.to_bytes();
            if open_owners.contains(&owner_key) || merge_backoff.contains_key(&owner_key) {
                continue;
            }
            for (asset_id, _mint) in self.assets() {
                match self.try_merge_asset(
                    *vka_address,
                    vka,
                    *asset_id,
                    inflight_spent,
                    settled,
                    skipped,
                ) {
                    Ok(Some(merged_inputs)) => {
                        inflight_spent.extend(merged_inputs);
                    }
                    // Nothing mergeable (<=1 spendable input) or aborted by a
                    // freshly opened proposal: no backoff, retry next tick.
                    Ok(None) => {}
                    Err(err) => {
                        let backoff = if is_merge_authority_not_whitelisted(&err) {
                            MERGE_BACKOFF_PERMANENT
                        } else {
                            MERGE_BACKOFF_TRANSIENT
                        };
                        merge_backoff.insert(owner_key, Instant::now() + backoff);
                        // A per-owner backoff is set; do not hammer other assets
                        // for this owner this tick.
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Attempt to consolidate one owner's spendable UTXOs of a single asset into
    /// one output. Returns the merged input utxo hashes on a successful send,
    /// `None` when there is nothing to merge (`<=1` spendable) or the merge was
    /// aborted because a proposal for this owner opened while proving.
    #[allow(clippy::too_many_arguments)]
    fn try_merge_asset(
        &self,
        vka_address: Address,
        vka: &ViewingKeyAccount,
        asset_id: u64,
        inflight_spent: &HashSet<[u8; 32]>,
        settled: &HashSet<[u8; 32]>,
        skipped: &HashSet<[u8; 32]>,
    ) -> Result<Option<Vec<[u8; 32]>>> {
        let mint = self.mint_for_asset_id(asset_id).ok_or_else(|| {
            SquadsBackendError::Unsupported(format!("unknown asset_id {asset_id}"))
        })?;

        let spendable: Vec<crate::types::DecryptedUtxo> = self
            .spendable_utxos(vka_address, asset_id)?
            .into_iter()
            .filter(|utxo| !inflight_spent.contains(&utxo.utxo_hash))
            .take(MERGE_INPUT_COUNT)
            .collect();
        if spendable.len() <= 1 {
            return Ok(None);
        }

        let resolved = self.resolve_shared_key_from_vka(vka.clone())?;
        let nullifier_key = NullifierKey::from_secret(resolved.nullifier_secret);

        let mut inputs = Vec::with_capacity(spendable.len());
        for utxo in &spendable {
            inputs.push(SquadsMergeInput {
                asset: mint,
                amount: utxo.amount,
                blinding: utxo.blinding,
                spend_proof: self.spend_proof(utxo, &nullifier_key)?,
            });
        }

        let proof = prove_squads_merge(SquadsMergeRequest {
            owner_field: vka.owner.to_bytes(),
            nullifier_secret: resolved.nullifier_secret,
            viewing_secret: resolved.shared_viewing_sk.clone(),
            nullifier_pubkey: vka.nullifier_pubkey,
            inputs,
            asset: mint,
            expiry_unix_ts: current_unix_ts().saturating_add(MERGE_EXPIRY_WINDOW_SECS),
            merge_view_tag: account_view_tag(vka),
            prover_url: self.prover_url().to_string(),
        })?;

        // Proving takes seconds; re-scan for a proposal that opened meanwhile. If
        // the owner now has an open proposal, abort so its settlement -- not this
        // merge -- spends the inputs.
        if self.owner_has_open_proposal(vka.owner, settled, skipped)? {
            return Ok(None);
        }

        let data = MergeTransactIxData {
            spp_proof: proof.spp_proof,
            expiry_unix_ts: proof.expiry_unix_ts,
            merge_view_tag: proof.merge_view_tag,
            private_tx_hash: proof.private_tx_hash,
            output_utxo_hash: proof.output_utxo_hash,
            input_contexts: proof.input_contexts,
            encrypted_utxo: proof.encrypted_utxo,
        };

        let ix = MergeTransact {
            merge_authority: self.relayer_pubkey(),
            zone_config: to_pubkey(self.zone_config()),
            owner_viewing_key_account: to_pubkey(vka_address),
            zone_auth: self.zone_auth_pubkey(),
            spp_program: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            tree_accounts: vec![to_pubkey(self.tree())],
            data,
        }
        .instruction();

        self.send_execute(ix)?;
        Ok(Some(
            spendable.into_iter().map(|utxo| utxo.utxo_hash).collect(),
        ))
    }

    /// Whether `owner` currently has an OPEN proposal (a `Proposal` PDA present in
    /// a fresh scan that the crank has neither settled nor skipped). Used to abort
    /// a merge whose proving overlapped a newly created proposal.
    fn owner_has_open_proposal(
        &self,
        owner: Address,
        settled: &HashSet<[u8; 32]>,
        skipped: &HashSet<[u8; 32]>,
    ) -> Result<bool> {
        let program_id = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);
        for (pda, account) in self.rpc().get_program_accounts(program_id)? {
            if account.data.first() != Some(&Proposal::DISCRIMINATOR) {
                continue;
            }
            let Ok(proposal) = Proposal::deserialize(&account.data) else {
                continue;
            };
            let key = pda.to_bytes();
            if proposal.owner == owner && !settled.contains(&key) && !skipped.contains(&key) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Prove and settle one reconstructed proposal on the smart-account rail.
    fn settle_proposal(&self, pda: Address, proposal: &Proposal) -> Result<()> {
        let reconstructed = self.reconstruct_zone_proposal(pda, proposal)?;

        // The smart-account settlement proof spends with the raw vault; confirm it
        // hashes to the stored owner field before proving.
        let vault_field = hash_field(&reconstructed.sender_vault.to_bytes())
            .map_err(|e| SquadsBackendError::Crypto(format!("vault owner field: {e:?}")))?;
        if vault_field != reconstructed.owner.to_bytes() {
            return Err(SquadsBackendError::Unsupported(format!(
                "proposal {pda} rent_payer does not hash to the owner field"
            )));
        }

        let (sender_vka_address, sender_vka) = self
            .find_viewing_key_account_by_owner(reconstructed.owner)?
            .ok_or_else(|| {
                SquadsBackendError::AccountNotFound(format!(
                    "sender viewing key account for owner {}",
                    reconstructed.owner
                ))
            })?;
        let sender = self.resolve_shared_key_from_vka(sender_vka.clone())?;
        let identity = SquadsSmartAccountIdentity {
            owner_vault: reconstructed.sender_vault,
            nullifier_secret: sender.nullifier_secret,
            viewing_secret: sender.shared_viewing_sk.clone(),
        };
        let sender_view_tag = account_view_tag(&sender.account);
        let nullifier_key = NullifierKey::from_secret(sender.nullifier_secret);

        let mint = self
            .mint_for_asset_id(reconstructed.asset_id)
            .ok_or_else(|| {
                SquadsBackendError::Unsupported(format!(
                    "unknown asset_id {}",
                    reconstructed.asset_id
                ))
            })?;

        let spendable = self.spendable_utxos(sender_vka_address, reconstructed.asset_id)?;

        let ix = match reconstructed.op {
            OP_TRANSFER => self.build_transfer_settlement(
                &reconstructed,
                sender_vka_address,
                identity,
                &nullifier_key,
                sender_view_tag,
                mint,
                &spendable,
            )?,
            OP_WITHDRAW => self.build_withdrawal_settlement(
                &reconstructed,
                sender_vka_address,
                identity,
                &nullifier_key,
                sender_view_tag,
                mint,
                &spendable,
            )?,
            other => {
                return Err(SquadsBackendError::Unsupported(format!(
                    "unknown proposal op {other}"
                )))
            }
        };

        self.send_execute(ix)?;
        Ok(())
    }

    /// The unspent UTXOs of one asset for a viewing key account (auditor decrypt).
    fn spendable_utxos(
        &self,
        viewing_key_account: Address,
        asset_id: u64,
    ) -> Result<Vec<crate::types::DecryptedUtxo>> {
        let balances = self.get_balances(GetBalancesRequest {
            viewing_key_account,
            skip_utxos: false,
            signature: [0u8; 64],
        })?;
        Ok(balances
            .balances
            .into_iter()
            .find(|b| b.asset_id == asset_id)
            .map(|b| b.utxos)
            .unwrap_or_default())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_transfer_settlement(
        &self,
        reconstructed: &ReconstructedProposal,
        sender_vka_address: Address,
        identity: SquadsSmartAccountIdentity,
        nullifier_key: &NullifierKey,
        sender_view_tag: [u8; 32],
        mint: Address,
        spendable: &[crate::types::DecryptedUtxo],
    ) -> Result<Instruction> {
        let (recipient_vka_address, recipient_vka) = self
            .find_viewing_key_account_by_owner(reconstructed.recipient)?
            .ok_or_else(|| {
                SquadsBackendError::AccountNotFound(format!(
                    "recipient viewing key account for owner {}",
                    reconstructed.recipient
                ))
            })?;
        let recipient = self.transfer_recipient(&recipient_vka)?;
        let recipient_view_tag =
            view_tag_from_shared_viewing_key(&recipient_vka.shared_viewing_key);

        // A single input that already covers the transfer is spent alone (the prover
        // synthesizes the paired dummy so the shape stays (2, 2)); otherwise fall back
        // to a covering pair.
        let first = spendable.first().ok_or_else(|| {
            SquadsBackendError::Unsupported("no spendable input for transfer".into())
        })?;
        let mut inputs = vec![SquadsTransferInput {
            asset: mint,
            amount: first.amount,
            blinding: first.blinding,
            spend_proof: self.spend_proof(first, nullifier_key)?,
        }];
        if first.amount < reconstructed.amount {
            let second = spendable
                .iter()
                .skip(1)
                .find(|u| first.amount.saturating_add(u.amount) >= reconstructed.amount)
                .ok_or_else(|| {
                    SquadsBackendError::Unsupported("no inputs cover the transferred amount".into())
                })?;
            inputs.push(SquadsTransferInput {
                asset: mint,
                amount: second.amount,
                blinding: second.blinding,
                spend_proof: self.spend_proof(second, nullifier_key)?,
            });
        }

        let salt = random_salt();
        let proof = prove_squads_smart_account_transfer(SquadsSmartAccountTransferRequest {
            identity,
            inputs,
            recipient,
            transferred: reconstructed.amount,
            recipient_blinding: random_blinding(),
            payer_pubkey_hash: self.payer_pubkey_hash(),
            expiry_unix_ts: reconstructed.expiry as u64,
            salt,
            sender_view_tag,
            recipient_view_tag,
            proposal: Some(reconstructed.zone_proposal.clone()),
            prover_url: self.prover_url().to_string(),
        })?;

        let input_contexts = proof
            .nullifiers
            .iter()
            .zip(proof.input_root_indices.iter())
            .map(
                |(nullifier, (utxo_root_index, nullifier_root_index))| InputContext {
                    nullifier: *nullifier,
                    tree_index: 0,
                    utxo_root_index: *utxo_root_index,
                    nullifier_root_index: *nullifier_root_index,
                },
            )
            .collect();

        let data = ExecuteProposalIxData {
            zone_proof: proof.zone_proof,
            spp_proof: proof.spp_proof,
            public_amount: None,
            private_tx_hash: proof.private_tx_hash,
            salt,
            output_view_tags: vec![sender_view_tag, recipient_view_tag],
            output_utxo_hashes: vec![proof.change_utxo_hash, proof.recipient_utxo_hash],
            input_contexts,
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: proof.tx_viewing_pk,
                sender_ciphertext: proof.sender_ciphertext,
                recipient_ciphertexts: vec![proof.recipient_ciphertext],
            },
        };

        Ok(self.execute_proposal_instruction(
            reconstructed,
            sender_vka_address,
            Some(recipient_vka_address),
            None,
            data,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_withdrawal_settlement(
        &self,
        reconstructed: &ReconstructedProposal,
        sender_vka_address: Address,
        identity: SquadsSmartAccountIdentity,
        nullifier_key: &NullifierKey,
        sender_view_tag: [u8; 32],
        mint: Address,
        spendable: &[crate::types::DecryptedUtxo],
    ) -> Result<Instruction> {
        let is_spl = reconstructed.asset_id != SOL_ASSET_ID;
        if is_spl {
            // The proposal does not bind a public SPL destination, so the crank
            // cannot know which token account to credit; SPL withdrawal settlement
            // is out of scope for the mock crank.
            return Err(SquadsBackendError::Unsupported(
                "crank SPL withdrawal settlement is unsupported (no bound token destination)"
                    .into(),
            ));
        }

        let input = spendable
            .iter()
            .find(|u| u.amount >= reconstructed.public_amount)
            .ok_or_else(|| {
                SquadsBackendError::Unsupported("no spendable input covers the withdrawal".into())
            })?;

        // The public destination is the sender's own vault (the proposal binds only
        // the public amount, not the recipient, for a withdrawal).
        let recipient = to_pubkey(reconstructed.sender_vault);
        let sol_interface = pda::sol_interface();
        let salt = random_salt();

        let proof = prove_squads_smart_account_withdrawal(SquadsSmartAccountWithdrawalRequest {
            identity,
            input: SquadsWithdrawalInput {
                asset: mint,
                amount: input.amount,
                blinding: input.blinding,
                spend_proof: self.spend_proof(input, nullifier_key)?,
            },
            withdrawn: reconstructed.public_amount,
            is_spl: false,
            user_sol_account: reconstructed.sender_vault,
            user_spl_token: Address::default(),
            spl_token_interface: Address::default(),
            payer_pubkey_hash: self.payer_pubkey_hash(),
            expiry_unix_ts: reconstructed.expiry as u64,
            salt,
            sender_view_tag,
            proposal: Some(reconstructed.zone_proposal.clone()),
            prover_url: self.prover_url().to_string(),
        })?;

        let data = ExecuteProposalIxData {
            zone_proof: proof.zone_proof,
            spp_proof: proof.spp_proof,
            public_amount: Some(reconstructed.public_amount),
            private_tx_hash: proof.private_tx_hash,
            salt,
            output_view_tags: vec![sender_view_tag],
            output_utxo_hashes: vec![proof.change_utxo_hash],
            input_contexts: vec![InputContext {
                nullifier: proof.nullifier,
                tree_index: 0,
                utxo_root_index: proof.utxo_root_index,
                nullifier_root_index: proof.nullifier_root_index,
            }],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: [0u8; 33],
                sender_ciphertext: proof.sender_ciphertext,
                recipient_ciphertexts: vec![],
            },
        };

        let withdrawal = TransactWithdrawal::Sol {
            sol_interface,
            recipient,
        };

        Ok(self.execute_proposal_instruction(
            reconstructed,
            sender_vka_address,
            None,
            Some(withdrawal),
            data,
        ))
    }

    /// Assemble the `execute_proposal` instruction with the relayer as payer and
    /// co-signer, the vault as rent recipient, and the derived zone/tree accounts.
    fn execute_proposal_instruction(
        &self,
        reconstructed: &ReconstructedProposal,
        sender_vka_address: Address,
        recipient_vka_address: Option<Address>,
        withdrawal: Option<TransactWithdrawal>,
        data: ExecuteProposalIxData,
    ) -> Instruction {
        let relayer = self.relayer_pubkey();
        ExecuteProposal {
            payer: relayer,
            co_signer: relayer,
            zone_config: to_pubkey(self.zone_config()),
            proposal: to_pubkey(reconstructed.pda),
            sender_viewing_key_account: to_pubkey(sender_vka_address),
            recipient_viewing_key_account: recipient_vka_address.map(to_pubkey),
            withdrawal,
            rent_recipient: to_pubkey(reconstructed.sender_vault),
            zone_auth: self.zone_auth_pubkey(),
            spp_program: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            tree_accounts: vec![to_pubkey(self.tree())],
            data,
        }
        .instruction()
    }

    /// Send `[budget, execute_proposal]` as a v0 transaction over a freshly built
    /// address lookup table, signed by the relayer (payer + co-signer).
    fn send_execute(&self, ix: Instruction) -> Result<()> {
        let relayer = self.relayer_pubkey();
        let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let instructions = [budget, ix];

        // Every non-signer, non-program account goes into the lookup table.
        let program_ids: HashSet<Pubkey> = instructions.iter().map(|i| i.program_id).collect();
        let mut seen: HashSet<Pubkey> = HashSet::new();
        let mut alt_addresses: Vec<Pubkey> = Vec::new();
        for instruction in &instructions {
            for meta in &instruction.accounts {
                if meta.pubkey != relayer
                    && !program_ids.contains(&meta.pubkey)
                    && seen.insert(meta.pubkey)
                {
                    alt_addresses.push(meta.pubkey);
                }
            }
        }

        let alt = self.create_alt(&alt_addresses)?;
        let relayer_address = Address::new_from_array(relayer.to_bytes());
        self.rpc().create_and_send_versioned_transaction(
            &instructions,
            relayer_address,
            &[self.zone_authority()],
            &[alt],
        )?;
        Ok(())
    }

    /// Create and activate an address lookup table over `addresses` using only
    /// `Rpc` trait methods (the suite's helper is unreachable from this crate). The
    /// relayer is both the table authority and the funder.
    fn create_alt(&self, addresses: &[Pubkey]) -> Result<AddressLookupTableAccount> {
        let authority = self.relayer_pubkey();
        let authority_address = Address::new_from_array(authority.to_bytes());
        let signer = self.zone_authority();

        // `create_lookup_table` needs a slot already in SlotHashes; the tip is not
        // yet there, so use its parent.
        let recent_slot = self.rpc().get_slot()?.saturating_sub(1);
        let (create_ix, table) = create_lookup_table(authority, authority, recent_slot);
        self.rpc()
            .create_and_send_transaction(&[create_ix], authority_address, &[signer])?;

        let extend_ix = extend_lookup_table(table, authority, Some(authority), addresses.to_vec());
        self.rpc()
            .create_and_send_transaction(&[extend_ix], authority_address, &[signer])?;

        // A table is usable only after the validator advances past the slot it was
        // last extended in.
        let activation_slot = self.rpc().get_slot()?.saturating_add(2);
        let started = Instant::now();
        loop {
            if self.rpc().get_slot()? >= activation_slot {
                break;
            }
            if started.elapsed() > ALT_ACTIVATION_TIMEOUT {
                return Err(SquadsBackendError::Unsupported(format!(
                    "lookup table {table} did not activate in time"
                )));
            }
            thread::sleep(Duration::from_millis(200));
        }

        let account = self
            .rpc()
            .get_account(Address::new_from_array(table.to_bytes()))?
            .ok_or_else(|| SquadsBackendError::AccountNotFound(table.to_string()))?;
        let parsed = AddressLookupTable::deserialize(&account.data).map_err(|e| {
            SquadsBackendError::Crypto(format!("deserialize lookup table {table}: {e}"))
        })?;
        Ok(AddressLookupTableAccount {
            key: table,
            addresses: parsed.addresses.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use zolana_client::ClientError;

    use super::*;

    fn proposal_for_owner(owner: Address) -> Proposal {
        Proposal::new(
            owner,
            Address::default(),
            Address::default(),
            [0u8; 32],
            [0u8; 88],
            0,
            Address::default(),
        )
    }

    fn owner(byte: u8) -> Address {
        Address::new_from_array([byte; 32])
    }

    fn pda(byte: u8) -> Address {
        Address::new_from_array([byte; 32])
    }

    #[test]
    fn whitelist_error_is_classified_as_permanent() {
        let err = SquadsBackendError::Client(ClientError::Rpc(
            "send_transaction: Error processing Instruction 0: custom program error: 0x1f55".into(),
        ));
        assert!(is_merge_authority_not_whitelisted(&err));
    }

    #[test]
    fn other_custom_error_is_not_classified_as_whitelist() {
        let err = SquadsBackendError::Client(ClientError::Rpc(
            "send_transaction: Error processing Instruction 0: custom program error: 0x1f56".into(),
        ));
        assert!(!is_merge_authority_not_whitelisted(&err));
    }

    #[test]
    fn non_custom_error_is_not_classified_as_whitelist() {
        let err = SquadsBackendError::Unsupported("no spendable input".into());
        assert!(!is_merge_authority_not_whitelisted(&err));
    }

    #[test]
    fn open_owners_exclude_settled_and_skipped() {
        let open_owner = owner(1);
        let settled_owner = owner(2);
        let skipped_owner = owner(3);
        let proposals = vec![
            (pda(10), proposal_for_owner(open_owner)),
            (pda(11), proposal_for_owner(settled_owner)),
            (pda(12), proposal_for_owner(skipped_owner)),
        ];
        let settled: HashSet<[u8; 32]> = [pda(11).to_bytes()].into_iter().collect();
        let skipped: HashSet<[u8; 32]> = [pda(12).to_bytes()].into_iter().collect();

        let open = open_proposal_owners(&proposals, &settled, &skipped);
        assert_eq!(open.len(), 1);
        assert!(open.contains(&open_owner.to_bytes()));
        assert!(!open.contains(&settled_owner.to_bytes()));
        assert!(!open.contains(&skipped_owner.to_bytes()));
    }

    #[test]
    fn partition_splits_by_discriminator() {
        let mut proposal_bytes = proposal_for_owner(owner(1)).serialize().expect("serialize");
        assert_eq!(
            proposal_bytes.first().copied(),
            Some(Proposal::DISCRIMINATOR)
        );

        let junk = Account {
            lamports: 0,
            data: vec![0xAB, 0xCD],
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        };
        let proposal_account = Account {
            lamports: 0,
            data: std::mem::take(&mut proposal_bytes),
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        };

        let (proposals, vkas) =
            partition_zone_accounts(vec![(pda(10), proposal_account), (pda(20), junk)]);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals.first().map(|(_, p)| p.owner), Some(owner(1)));
        assert!(vkas.is_empty());
    }
}
