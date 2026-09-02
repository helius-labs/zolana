use std::{thread, time::Duration};

use anyhow::{anyhow, bail, Result};
use solana_account::Account;
use solana_commitment_config::CommitmentConfig;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_api::{BlockingZolanaApi, NullifierQueueElement, SerializablePubkey, PAGE_LIMIT};
use zolana_interface::{instruction::CloseNullifierPdas, pda, NULLIFIER_PDA_SIZE};
use zolana_smart_account_client::{execute_sync_ix, smart_account_pda};
use zolana_tree::TreeAccount;

use crate::config::ForesterConfig;

pub const LEGACY_TRANSACTION_SIZE_LIMIT: usize = 1232;
pub const MULTIPLE_ACCOUNTS_CHUNK: usize = 100;

pub struct CloseNullifierPdasOptions {
    pub tree: Pubkey,
    pub settings: Pubkey,
    pub account_index: u8,
    pub from_seq: u64,
    pub max_transactions: Option<u64>,
    pub watch: bool,
    pub poll_secs: u64,
}

/// The forester smart account: the vault at `account_index` is the tree's
/// `forester_authority`, and `member` signs the outer transaction, pays its
/// fee, and receives the close reimbursement.
#[derive(Clone, Copy, Debug)]
pub struct ForesterSmartAccount {
    pub settings: Pubkey,
    pub account_index: u8,
    pub member: Pubkey,
}

impl ForesterSmartAccount {
    pub fn vault(&self) -> Pubkey {
        smart_account_pda(&self.settings, self.account_index).0
    }
}

pub struct CloseNullifierPdasBatch {
    pub tree: Pubkey,
    pub forester: ForesterSmartAccount,
    pub nullifiers: Vec<[u8; 32]>,
}

impl CloseNullifierPdasBatch {
    pub fn inner_instruction(&self) -> Instruction {
        CloseNullifierPdas {
            authority: self.forester.vault(),
            tree: self.tree,
            reimbursement_recipient: self.forester.member,
            nullifiers: self.nullifiers.clone(),
        }
        .instruction()
    }

    pub fn instruction(&self) -> Instruction {
        execute_sync_ix(
            &self.forester.settings,
            self.forester.account_index,
            &[self.forester.member],
            &[self.inner_instruction()],
        )
    }

    pub fn message(&self) -> Message {
        Message::new(&[self.instruction()], Some(&self.forester.member))
    }

    pub fn serialized_size(&self) -> Result<usize> {
        let transaction = Transaction::new_unsigned(self.message());
        let bytes = wincode::serialize(&transaction)
            .map_err(|err| anyhow!("serialize close-nullifier-pdas transaction: {err}"))?;
        Ok(bytes.len())
    }

    pub fn fits(&self) -> Result<bool> {
        Ok(self.serialized_size()? <= LEGACY_TRANSACTION_SIZE_LIMIT)
    }

    fn submit(&self, rpc: &RpcClient, member: &Keypair) -> Result<Signature> {
        let blockhash = rpc
            .get_latest_blockhash()
            .map_err(|err| anyhow!("fetch latest blockhash: {err}"))?;
        let transaction = Transaction::new(&[member], self.message(), blockhash);
        rpc.send_and_confirm_transaction(&transaction)
            .map_err(|err| anyhow!("close {} nullifier PDAs: {err}", self.nullifiers.len()))
    }
}

pub fn plan_batches(
    tree: Pubkey,
    forester: ForesterSmartAccount,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<CloseNullifierPdasBatch>> {
    if nullifiers.is_empty() {
        return Ok(Vec::new());
    }

    let capacity = nullifier_pda_capacity(tree, forester)?;
    Ok(nullifiers
        .chunks(capacity)
        .map(|chunk| CloseNullifierPdasBatch {
            tree,
            forester,
            nullifiers: chunk.to_vec(),
        })
        .collect())
}

/// Compute the worst-case nullifier PDA capacity once per plan. Message size depends
/// on the number of unique accounts, not their key bytes, so deterministic
/// unique nullifier PDA PDAs avoid re-deriving and re-serializing the growing batch
/// for every queued nullifier.
fn nullifier_pda_capacity(tree: Pubkey, forester: ForesterSmartAccount) -> Result<usize> {
    let mut nullifiers = Vec::new();
    for sequence in 0..=u8::MAX as u64 {
        let mut nullifier = [0u8; 32];
        nullifier[24..].copy_from_slice(&sequence.to_be_bytes());
        nullifiers.push(nullifier);
        let candidate = CloseNullifierPdasBatch {
            tree,
            forester,
            nullifiers: nullifiers.clone(),
        };
        if candidate.fits()? {
            continue;
        }
        let capacity = nullifiers.len().saturating_sub(1);
        if capacity == 0 {
            bail!("a single nullifier PDA does not fit in one transaction");
        }
        return Ok(capacity);
    }
    bail!("legacy transaction size limit did not bound nullifier PDA account count")
}

pub fn retain_open_accounts(
    nullifiers: &[[u8; 32]],
    accounts: &[Option<Account>],
) -> Result<Vec<[u8; 32]>> {
    if nullifiers.len() != accounts.len() {
        bail!(
            "rpc returned {} accounts for {} nullifier PDAs",
            accounts.len(),
            nullifiers.len()
        );
    }
    let program_id = pda::shielded_pool_program_id();
    Ok(nullifiers
        .iter()
        .zip(accounts)
        .filter(|(_, account)| {
            account.as_ref().is_some_and(|account| {
                account.owner == program_id && account.data.len() == NULLIFIER_PDA_SIZE
            })
        })
        .map(|(nullifier, _)| *nullifier)
        .collect())
}

pub fn collect_queued_pages(
    start_seq: u64,
    end_seq: u64,
    mut fetch_page: impl FnMut(u64, u64) -> Result<Vec<NullifierQueueElement>>,
) -> Result<Vec<NullifierQueueElement>> {
    let mut elements = Vec::new();
    let mut next_seq = start_seq;
    while next_seq < end_seq {
        let limit = (end_seq - next_seq).min(PAGE_LIMIT);
        let page = fetch_page(next_seq, limit)?;
        let returned =
            u64::try_from(page.len()).map_err(|_| anyhow!("photon page length exceeds u64"))?;
        if returned > limit {
            bail!("photon returned {returned} queued nullifiers after sequence {next_seq}, requested at most {limit}");
        }
        for element in page {
            if element.seq != next_seq {
                bail!(
                    "queued nullifier sequence gap: expected {next_seq}, photon returned {}",
                    element.seq
                );
            }
            elements.push(element);
            next_seq = next_seq
                .checked_add(1)
                .ok_or_else(|| anyhow!("queued nullifier sequence overflow"))?;
        }
        if returned < limit {
            break;
        }
    }
    Ok(elements)
}

struct ClosePass {
    submitted: u64,
    closed_before: u64,
}

pub fn run(config: &ForesterConfig, opts: CloseNullifierPdasOptions) -> Result<()> {
    let rpc = RpcClient::new_with_commitment(config.rpc_url.clone(), CommitmentConfig::confirmed());
    let photon = BlockingZolanaApi::new(config.photon_url.clone());
    let member = config.signer()?;
    let forester = ForesterSmartAccount {
        settings: opts.settings,
        account_index: opts.account_index,
        member: member.pubkey(),
    };

    tracing::info!(
        tree = %opts.tree,
        member = %forester.member,
        vault = %forester.vault(),
        "forester close-nullifier-pdas"
    );

    let mut submitted_total = 0u64;
    let mut scan_from = opts.from_seq;
    loop {
        let remaining = opts
            .max_transactions
            .map(|max| max.saturating_sub(submitted_total));
        if matches!(remaining, Some(0)) {
            tracing::info!(submitted_total, "reached --max-transactions cap");
            break;
        }

        let pass = match close_once(
            &rpc, &photon, &member, forester, opts.tree, scan_from, remaining,
        ) {
            Ok(pass) => pass,
            Err(error) if opts.watch => {
                tracing::warn!(%error, scan_from, "close-nullifier-pdas pass failed; retrying");
                thread::sleep(Duration::from_secs(opts.poll_secs));
                continue;
            }
            Err(error) => return Err(error),
        };
        submitted_total += pass.submitted;
        scan_from = pass.closed_before;

        if !opts.watch {
            break;
        }
        if pass.submitted == 0 {
            thread::sleep(Duration::from_secs(opts.poll_secs));
        }
    }

    tracing::info!(submitted_total, "forester close-nullifier-pdas complete");
    Ok(())
}

fn close_once(
    rpc: &RpcClient,
    photon: &BlockingZolanaApi,
    member: &Keypair,
    forester: ForesterSmartAccount,
    tree: Pubkey,
    scan_from: u64,
    limit: Option<u64>,
) -> Result<ClosePass> {
    let close_before_index = read_close_before_index(rpc, tree)?;
    if scan_from >= close_before_index {
        tracing::info!(close_before_index, "no closable nullifier PDAs to close");
        return Ok(ClosePass {
            submitted: 0,
            closed_before: scan_from,
        });
    }

    let elements = fetch_queued_before(photon, tree, scan_from, close_before_index)?;
    let indexed_before = scan_from.saturating_add(
        u64::try_from(elements.len()).map_err(|_| anyhow!("queued nullifier count exceeds u64"))?,
    );
    if indexed_before < close_before_index {
        tracing::warn!(
            indexed_before,
            close_before_index,
            "photon has not indexed every closable nullifier yet"
        );
    }

    let candidates: Vec<[u8; 32]> = elements
        .into_iter()
        .map(|element| element.value.0)
        .collect();
    let open = retain_open_nullifier_pdas(rpc, tree, &candidates)?;
    let batches = plan_batches(tree, forester, &open)?;
    tracing::info!(
        close_before_index,
        candidates = candidates.len(),
        open = open.len(),
        transactions = batches.len(),
        "planned nullifier PDA cleanup"
    );

    let mut submitted = 0u64;
    let mut capped = false;
    for batch in &batches {
        if limit.is_some_and(|limit| submitted >= limit) {
            capped = true;
            break;
        }
        if let Some((signature, nullifier_pdas)) = submit_race_tolerant(rpc, member, batch)? {
            submitted += 1;
            tracing::info!(%signature, nullifier_pdas, "closed nullifier PDAs");
        }
    }

    let closed_before = if capped { scan_from } else { indexed_before };
    Ok(ClosePass {
        submitted,
        closed_before,
    })
}

/// Submit a planned batch and recover from another forester instance winning
/// the race. A failed transaction is retried only when a fresh account read
/// proves that at least one planned nullifier PDA disappeared; unrelated RPC or
/// program failures are returned unchanged.
fn submit_race_tolerant(
    rpc: &RpcClient,
    member: &Keypair,
    planned: &CloseNullifierPdasBatch,
) -> Result<Option<(Signature, usize)>> {
    let mut batch = CloseNullifierPdasBatch {
        tree: planned.tree,
        forester: planned.forester,
        nullifiers: planned.nullifiers.clone(),
    };
    loop {
        match batch.submit(rpc, member) {
            Ok(signature) => return Ok(Some((signature, batch.nullifiers.len()))),
            Err(submit_error) => {
                let open = retain_open_nullifier_pdas(rpc, batch.tree, &batch.nullifiers)?;
                if open.len() == batch.nullifiers.len() {
                    return Err(submit_error);
                }
                tracing::info!(
                    raced = batch.nullifiers.len() - open.len(),
                    remaining = open.len(),
                    "another forester removed nullifier PDAs; replanning batch"
                );
                if open.is_empty() {
                    return Ok(None);
                }
                batch.nullifiers = open;
            }
        }
    }
}

fn read_close_before_index(rpc: &RpcClient, tree: Pubkey) -> Result<u64> {
    let mut data = rpc
        .get_account_with_commitment(&tree, CommitmentConfig::confirmed())
        .map_err(|err| anyhow!("fetch tree account {tree}: {err}"))?
        .value
        .ok_or_else(|| anyhow!("tree account not found: {tree}"))?
        .data;
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|err| anyhow!("parse tree account {tree}: {err:?}"))?;
    Ok(account.close_before_index())
}

fn fetch_queued_before(
    photon: &BlockingZolanaApi,
    tree: Pubkey,
    start_seq: u64,
    close_before_index: u64,
) -> Result<Vec<NullifierQueueElement>> {
    let tree_account = SerializablePubkey(tree);
    collect_queued_pages(start_seq, close_before_index, |start_seq, limit| {
        photon
            .get_nullifier_queue_elements(tree_account, Some(start_seq), limit)
            .map(|response| response.elements)
            .map_err(|err| {
                anyhow!("fetch queued nullifiers from photon at sequence {start_seq}: {err}")
            })
    })
}

fn retain_open_nullifier_pdas(
    rpc: &RpcClient,
    tree: Pubkey,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>> {
    let mut open = Vec::with_capacity(nullifiers.len());
    for chunk in nullifiers.chunks(MULTIPLE_ACCOUNTS_CHUNK) {
        let addresses: Vec<Pubkey> = chunk
            .iter()
            .map(|nullifier| pda::nullifier_pda(&tree, nullifier).0)
            .collect();
        let accounts = rpc
            .get_multiple_accounts(&addresses)
            .map_err(|err| anyhow!("fetch nullifier PDA accounts: {err}"))?;
        open.extend(retain_open_accounts(chunk, &accounts)?);
    }
    Ok(open)
}
