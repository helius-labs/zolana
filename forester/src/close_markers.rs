use std::{thread, time::Duration};

use anyhow::{anyhow, bail, Result};
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
use zolana_interface::{instruction::CloseNullifierMarkers, pda};
use zolana_tree::TreeAccount;

use crate::config::ForesterConfig;

pub const LEGACY_TRANSACTION_SIZE_LIMIT: usize = 1232;
pub const MULTIPLE_ACCOUNTS_CHUNK: usize = 100;

pub struct CloseMarkersOptions {
    pub tree: Pubkey,
    pub max_transactions: Option<u64>,
    pub watch: bool,
    pub poll_secs: u64,
}

pub struct CloseMarkersBatch {
    pub tree: Pubkey,
    pub payer: Pubkey,
    pub nullifiers: Vec<[u8; 32]>,
}

impl CloseMarkersBatch {
    pub fn instruction(&self) -> Instruction {
        CloseNullifierMarkers {
            tree: self.tree,
            nullifiers: self.nullifiers.clone(),
        }
        .instruction()
    }

    pub fn message(&self) -> Message {
        Message::new(&[self.instruction()], Some(&self.payer))
    }

    pub fn serialized_size(&self) -> Result<usize> {
        let transaction = Transaction::new_unsigned(self.message());
        let bytes = wincode::serialize(&transaction)
            .map_err(|err| anyhow!("serialize close-markers transaction: {err}"))?;
        Ok(bytes.len())
    }

    pub fn fits(&self) -> Result<bool> {
        Ok(self.serialized_size()? <= LEGACY_TRANSACTION_SIZE_LIMIT)
    }

    fn submit(&self, rpc: &RpcClient, payer: &Keypair) -> Result<Signature> {
        let blockhash = rpc
            .get_latest_blockhash()
            .map_err(|err| anyhow!("fetch latest blockhash: {err}"))?;
        let transaction = Transaction::new(&[payer], self.message(), blockhash);
        rpc.send_and_confirm_transaction(&transaction)
            .map_err(|err| anyhow!("close {} nullifier markers: {err}", self.nullifiers.len()))
    }
}

pub fn closable_nullifiers(
    elements: impl IntoIterator<Item = NullifierQueueElement>,
    close_before_index: u64,
) -> Vec<[u8; 32]> {
    elements
        .into_iter()
        .filter(|element| element.seq < close_before_index)
        .map(|element| element.value.0)
        .collect()
}

pub fn plan_batches(
    tree: Pubkey,
    payer: Pubkey,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<CloseMarkersBatch>> {
    let mut batches = Vec::new();
    let mut current = CloseMarkersBatch {
        tree,
        payer,
        nullifiers: Vec::new(),
    };
    for nullifier in nullifiers.iter().copied() {
        current.nullifiers.push(nullifier);
        if current.fits()? {
            continue;
        }
        current.nullifiers.pop();
        if current.nullifiers.is_empty() {
            bail!("a single nullifier marker does not fit in one transaction");
        }
        let full = std::mem::replace(
            &mut current,
            CloseMarkersBatch {
                tree,
                payer,
                nullifiers: vec![nullifier],
            },
        );
        batches.push(full);
        if !current.fits()? {
            bail!("a single nullifier marker does not fit in one transaction");
        }
    }
    if !current.nullifiers.is_empty() {
        batches.push(current);
    }
    Ok(batches)
}

pub fn retain_existing<T>(
    nullifiers: &[[u8; 32]],
    accounts: &[Option<T>],
) -> Result<Vec<[u8; 32]>> {
    if nullifiers.len() != accounts.len() {
        bail!(
            "rpc returned {} accounts for {} nullifier markers",
            accounts.len(),
            nullifiers.len()
        );
    }
    Ok(nullifiers
        .iter()
        .zip(accounts)
        .filter(|(_, account)| account.is_some())
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

pub fn run(config: &ForesterConfig, opts: CloseMarkersOptions) -> Result<()> {
    let rpc = RpcClient::new_with_commitment(config.rpc_url.clone(), CommitmentConfig::confirmed());
    let photon = BlockingZolanaApi::new(config.photon_url.clone());
    let payer = config.signer()?;

    tracing::info!(tree = %opts.tree, payer = %payer.pubkey(), "forester close-markers");

    let mut submitted_total = 0u64;
    let mut scan_from = 0u64;
    loop {
        let remaining = opts
            .max_transactions
            .map(|max| max.saturating_sub(submitted_total));
        if matches!(remaining, Some(0)) {
            tracing::info!(submitted_total, "reached --max-transactions cap");
            break;
        }

        let pass = close_once(&rpc, &photon, &payer, opts.tree, scan_from, remaining)?;
        submitted_total += pass.submitted;
        scan_from = pass.closed_before;

        if !opts.watch {
            break;
        }
        if pass.submitted == 0 {
            thread::sleep(Duration::from_secs(opts.poll_secs));
        }
    }

    tracing::info!(submitted_total, "forester close-markers complete");
    Ok(())
}

fn close_once(
    rpc: &RpcClient,
    photon: &BlockingZolanaApi,
    payer: &Keypair,
    tree: Pubkey,
    scan_from: u64,
    limit: Option<u64>,
) -> Result<ClosePass> {
    let close_before_index = read_close_before_index(rpc, tree)?;
    if scan_from >= close_before_index {
        tracing::info!(close_before_index, "no retired nullifier markers to close");
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
            "photon has not indexed every retired nullifier yet"
        );
    }

    let candidates = closable_nullifiers(elements, close_before_index);
    let open = retain_open_markers(rpc, tree, &candidates)?;
    let batches = plan_batches(tree, payer.pubkey(), &open)?;
    tracing::info!(
        close_before_index,
        candidates = candidates.len(),
        open = open.len(),
        transactions = batches.len(),
        "planned nullifier marker cleanup"
    );

    let mut submitted = 0u64;
    let mut capped = false;
    for batch in &batches {
        if limit.is_some_and(|limit| submitted >= limit) {
            capped = true;
            break;
        }
        let signature = batch.submit(rpc, payer)?;
        submitted += 1;
        tracing::info!(
            %signature,
            markers = batch.nullifiers.len(),
            "closed nullifier markers"
        );
    }

    let closed_before = if capped { scan_from } else { indexed_before };
    Ok(ClosePass {
        submitted,
        closed_before,
    })
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

fn retain_open_markers(
    rpc: &RpcClient,
    tree: Pubkey,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>> {
    let mut open = Vec::with_capacity(nullifiers.len());
    for chunk in nullifiers.chunks(MULTIPLE_ACCOUNTS_CHUNK) {
        let addresses: Vec<Pubkey> = chunk
            .iter()
            .map(|nullifier| pda::nullifier_marker(&tree, nullifier).0)
            .collect();
        let accounts = rpc
            .get_multiple_accounts(&addresses)
            .map_err(|err| anyhow!("fetch nullifier marker accounts: {err}"))?;
        open.extend(retain_existing(chunk, &accounts)?);
    }
    Ok(open)
}
