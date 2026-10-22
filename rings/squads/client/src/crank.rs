//! Autonomous background settlement crank.
//!
//! [`SquadsBackend::new_with_crank`] spawns one thread that polls the ring program's
//! `Proposal` PDAs, reconstructs and verifies each against on-chain data plus the
//! auditor key ([`SquadsBackend::reconstruct_ring_proposal`]), gathers the sender's
//! spendable UTXOs, proves the smart-account (signatureless) settlement, and sends
//! `execute_proposal` as a v1 transaction. It settles both transfers and
//! withdrawals on the smart-account
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

use solana_account::Account;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc, ZolanaIndexer};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::NullifierKey;
use zolana_keypair::X25519Keypair;
use zolana_squads_interface::{
    error::SquadsRingError,
    instruction::{
        builders::{ExecuteProposal, MergeTransact},
        instruction_data::{ExecuteProposalIxData, MergeTransactIxData},
    },
    state::{Proposal, ViewingKeyAccount},
    SQUADS_RING_PROGRAM_ID,
};
use zolana_squads_sdk::prover::{
    merge_dummy_nullifiers, merge_first_nullifier, prove_squads_merge, SquadsMergeInput,
    SquadsMergeRequest, SquadsOwner,
};
use zolana_transaction::{instructions::merge::MERGE_DEFAULT_INPUT_COUNT, Address};

use crate::{
    backend::SquadsBackend,
    error::{Result, SquadsBackendError},
    proposals::{OP_TRANSFER, OP_WITHDRAW},
    transact::{SpendKind, SpendParams},
    types::GetBalancesRequest,
};

/// Poll cadence for the crank loop.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Compute-unit limit of a settlement transaction (two proof verifications).
const SETTLEMENT_CU_LIMIT: u32 = 1_400_000;
/// Validity window stamped on auto-merge proofs (SPP `merge_ring` enforces it
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
/// ring config error (a `ProgramError::Custom(8021)`), which surfaces in the send
/// error string as the hex custom-error code (`custom program error: 0x1f55`).
/// Any other error is treated as transient. Detection is best-effort string
/// matching on the code the runtime renders; a false negative only shortens the
/// backoff (the next tick retries), never causing an unsafe spend.
fn is_merge_authority_not_whitelisted(err: &SquadsBackendError) -> bool {
    let code = SquadsRingError::MergeAuthorityNotWhitelisted as u32;
    let hex = format!("0x{code:x}");
    err.to_string().to_ascii_lowercase().contains(&hex)
}

/// Decoded `Proposal` PDAs keyed by address, from one program-account scan.
type ProposalScan = Vec<(Address, Proposal)>;
/// Decoded `ViewingKeyAccount` PDAs keyed by address, from one program-account scan.
type ViewingKeyAccountScan = Vec<(Address, ViewingKeyAccount)>;

/// Split one ring program-account scan into `Proposal` and `ViewingKeyAccount`
/// PDAs by their leading discriminator byte, decoding each into its typed form.
/// Accounts of any other kind (or that fail to decode) are dropped.
fn partition_ring_accounts(
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
    /// settlement crank. The crank polls the ring program's `Proposal` PDAs,
    /// decrypts them with the auditor key, and settles them with the relayer;
    /// dropping the backend stops it. Crankless construction from pre-built
    /// indexer/RPC instances goes through [`SquadsBackend::new`].
    pub fn new_with_crank(
        auditor_sk: X25519Keypair,
        ring_authority: Keypair,
        ring_config: Address,
        tree_id: u16,
        prover_url: impl Into<String>,
        indexer_url: impl Into<String>,
        rpc_url: impl Into<String>,
    ) -> Self {
        let indexer_url = indexer_url.into();
        let rpc_url = rpc_url.into();
        Self::new(
            auditor_sk,
            ring_authority,
            ring_config,
            tree_id,
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
        let ring_authority = self.ring_authority().insecure_clone();
        let ring_config = self.ring_config();
        let tree_id = self.tree_id();
        let prover_url = self.prover_url().to_string();
        let assets: Vec<(u64, Address)> = self.assets().to_vec();
        let indexer_url = indexer_url.into();
        let rpc_url = rpc_url.into();

        let handle = thread::spawn(move || {
            let indexer = ZolanaIndexer::new(&indexer_url);
            let rpc = SolanaRpc::new(rpc_url);
            let mut backend = SquadsBackend::new(
                auditor,
                ring_authority,
                ring_config,
                tree_id,
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
        let program_id = Address::new_from_array(SQUADS_RING_PROGRAM_ID);
        let (proposals, viewing_key_accounts) =
            partition_ring_accounts(self.rpc().get_program_accounts(program_id)?);

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

        let mut spendable: Vec<crate::types::DecryptedUtxo> = self
            .spendable_utxos(vka_address, asset_id)?
            .into_iter()
            .filter(|utxo| !inflight_spent.contains(&utxo.utxo_hash))
            .collect();
        // A merge spends from one tree.
        let Some(tree_id) = spendable.first().map(|utxo| utxo.tree_id) else {
            return Ok(None);
        };
        spendable.retain(|utxo| utxo.tree_id == tree_id);
        spendable.truncate(MERGE_DEFAULT_INPUT_COUNT);
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
                tree_id: utxo.tree_id,
                leaf_index: utxo.leaf_index,
                spend_proof: self.spend_proof(utxo, &nullifier_key)?,
            });
        }
        let owner_identity = vka.owner.to_bytes();
        let first = inputs
            .first()
            .ok_or_else(|| SquadsBackendError::Unsupported("merge needs an input".into()))?;
        let first_nullifier = merge_first_nullifier(owner_identity, &nullifier_key, first)?;
        let dummy_nullifiers =
            merge_dummy_nullifiers(&nullifier_key, &first_nullifier, inputs.len())?;
        let dummy_nullifier_proofs = if dummy_nullifiers.is_empty() {
            Vec::new()
        } else {
            self.indexer()
                .get_non_inclusion_proofs(self.tree_for(tree_id), dummy_nullifiers, None)?
                .proofs
        };

        let viewing_pubkey = zolana_keypair::X25519Pubkey::from_bytes(vka.shared_viewing_key)
            .map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))?;
        let relayer = self.relayer_pubkey();
        let proof = prove_squads_merge(SquadsMergeRequest {
            owner_identity,
            nullifier_key,
            viewing_pubkey,
            inputs,
            dummy_nullifier_proofs,
            expiry_unix_ts: current_unix_ts().saturating_add(MERGE_EXPIRY_WINDOW_SECS),
            output_tree_id: self.tree_id(),
            payer: Address::new_from_array(relayer.to_bytes()),
            prover_url: self.prover_url().to_string(),
        })?;

        // Proving takes seconds; re-scan for a proposal that opened meanwhile. If
        // the owner now has an open proposal, abort so its settlement -- not this
        // merge -- spends the inputs.
        if self.owner_has_open_proposal(vka.owner, settled, skipped)? {
            return Ok(None);
        }

        let ix = MergeTransact {
            merge_authority: relayer,
            ring_config: to_pubkey(self.ring_config()),
            owner_viewing_key_account: to_pubkey(vka_address),
            spp_accounts: proof.spp_accounts,
            data: MergeTransactIxData { spp: proof.spp },
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
        let program_id = Address::new_from_array(SQUADS_RING_PROGRAM_ID);
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
        let reconstructed = self.reconstruct_ring_proposal(pda, proposal)?;

        // The vault receives the proposal rent back (and a withdrawal's funds);
        // it must be the account owner.
        let vault_identity = solana_owner_identity(reconstructed.sender_vault.as_array())
            .map_err(|e| SquadsBackendError::Crypto(format!("vault owner identity: {e:?}")))?;
        if vault_identity != reconstructed.owner.to_bytes() {
            return Err(SquadsBackendError::Unsupported(format!(
                "proposal {pda} rent_payer is not the owner vault"
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
        let sender = self.resolve_shared_key_from_vka(sender_vka)?;
        let spendable = self.spendable_utxos(sender_vka_address, reconstructed.asset_id)?;

        let (kind, inputs, recipient_vka_address) = match reconstructed.op {
            OP_TRANSFER => {
                let (recipient_vka_address, _) = self
                    .find_viewing_key_account_by_owner(reconstructed.recipient)?
                    .ok_or_else(|| {
                        SquadsBackendError::AccountNotFound(format!(
                            "recipient viewing key account for owner {}",
                            reconstructed.recipient
                        ))
                    })?;
                (
                    SpendKind::Transfer {
                        recipient_viewing_key_account: recipient_vka_address,
                        amount: reconstructed.amount,
                    },
                    covering_inputs(&spendable, reconstructed.amount, 2)?,
                    Some(recipient_vka_address),
                )
            }
            OP_WITHDRAW => {
                if reconstructed.asset_id != crate::backend::SOL_ASSET_ID {
                    // The proposal binds no public SPL destination, so the crank
                    // cannot know which token account to credit.
                    return Err(SquadsBackendError::Unsupported(
                        "crank SPL withdrawal settlement is unsupported (no bound token destination)"
                            .into(),
                    ));
                }
                (
                    SpendKind::Withdrawal {
                        amount: reconstructed.public_amount,
                        recipient_account: reconstructed.sender_vault,
                    },
                    covering_inputs(&spendable, reconstructed.public_amount, 1)?,
                    None,
                )
            }
            other => {
                return Err(SquadsBackendError::Unsupported(format!(
                    "unknown proposal op {other}"
                )))
            }
        };

        let proof = self
            .probe_spend(SpendParams {
                sender: &sender,
                owner: SquadsOwner::SmartAccount,
                inputs: &inputs,
                kind,
                expiry: reconstructed.expiry,
                proposal: Some(reconstructed.ring_proposal.clone()),
            })?
            .finalize(None)?;

        let relayer = self.relayer_pubkey();
        let ix = ExecuteProposal {
            payer: relayer,
            co_signer: relayer,
            ring_config: to_pubkey(self.ring_config()),
            proposal: to_pubkey(reconstructed.pda),
            sender_viewing_key_account: to_pubkey(sender_vka_address),
            recipient_viewing_key_account: recipient_vka_address.map(to_pubkey),
            rent_recipient: to_pubkey(reconstructed.sender_vault),
            spp_accounts: proof.spp_accounts,
            data: ExecuteProposalIxData {
                ring_proof: proof.ring_proof,
                spp: proof.spp,
            },
        }
        .instruction();
        self.send_execute(ix)
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

    /// Send `execute_proposal` / `merge_transact` as a v1 transaction signed by
    /// the relayer (payer + co-signer / merge authority).
    fn send_execute(&self, ix: Instruction) -> Result<()> {
        let relayer = Address::new_from_array(self.relayer_pubkey().to_bytes());
        self.rpc().create_and_send_transaction(
            &[ix],
            relayer,
            &[self.ring_authority()],
            ComputeBudgetConfig::new(SETTLEMENT_CU_LIMIT),
        )?;
        Ok(())
    }
}

/// The inputs a settlement spends: the first UTXO when it covers `amount` (a
/// transfer pads it with a dummy slot), else a covering pair from one tree
/// when `max_inputs` allows it.
fn covering_inputs(
    spendable: &[crate::types::DecryptedUtxo],
    amount: u64,
    max_inputs: usize,
) -> Result<Vec<crate::types::DecryptedUtxo>> {
    if let Some(single) = spendable.iter().find(|utxo| utxo.amount >= amount) {
        return Ok(vec![*single]);
    }
    if max_inputs >= 2 {
        for (index, first) in spendable.iter().enumerate() {
            if let Some(second) = spendable.iter().skip(index + 1).find(|utxo| {
                utxo.tree_id == first.tree_id && first.amount.saturating_add(utxo.amount) >= amount
            }) {
                return Ok(vec![*first, *second]);
            }
        }
    }
    Err(SquadsBackendError::Unsupported(
        "no spendable inputs cover the amount".into(),
    ))
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
            partition_ring_accounts(vec![(pda(10), proposal_account), (pda(20), junk)]);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals.first().map(|(_, p)| p.owner), Some(owner(1)));
        assert!(vkas.is_empty());
    }
}
