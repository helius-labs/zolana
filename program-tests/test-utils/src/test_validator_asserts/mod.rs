pub mod create_spl_interface;
pub mod deposit;
pub mod merge_ring;
pub mod protocol_config;
pub mod ring_deposit;
pub mod ring_transact;
pub mod spl_deposit;
pub mod squads_deposit;
pub mod squads_withdrawal;

use std::time::{Duration, Instant};

pub use create_spl_interface::assert_create_spl_interface;
pub use deposit::{assert_deposit, DepositAssertArgs};
pub use merge_ring::{assert_merge_ring, MergeRingAssertArgs};
pub use protocol_config::assert_protocol_config;
pub use ring_deposit::{assert_ring_deposit, RingDepositAssertArgs};
pub use ring_transact::{assert_ring_transact, RingTransactAssertArgs};
use solana_account::Account;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
pub use spl_deposit::{assert_spl_deposit, SplDepositAssertArgs};
pub use squads_deposit::{assert_squads_deposit, SquadsDepositAssertArgs, SquadsDepositSettlement};
pub use squads_withdrawal::{
    assert_squads_withdrawal, SquadsWithdrawalAssertArgs, SquadsWithdrawalSettlement,
};
use zolana_client::{
    ClientError, EncryptedUtxoMatch, MerkleProof, NonInclusionProof, Rpc, ShieldedTransaction,
    SolanaRpc,
};
use zolana_interface::{instruction::AssetDeposit, state::state_root_offset};
use zolana_program_test::DepositOutput;

const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const TAG_PAGE_LIMIT: u32 = 100;
const TOKEN_ACCOUNT_AMOUNT_OFFSET: usize = 64;
const TOKEN_ACCOUNT_AMOUNT_END: usize = 72;

pub fn to_address(pubkey: &Pubkey) -> Address {
    Address::new_from_array(pubkey.to_bytes())
}

pub fn expected_deposit_view(
    data: &AssetDeposit,
    expected_amount: u64,
    expected_asset: Address,
    event: &DepositOutput,
) -> DepositOutput {
    DepositOutput {
        view_tag: data.view_tag,
        utxo_hash: event.utxo_hash,
        output_tree: event.output_tree,
        leaf_index: event.leaf_index,
        output: zolana_event::ProoflessOutput {
            owner: data.owner,
            blinding: data.blinding,
            asset: expected_asset.to_bytes(),
            amount: expected_amount,
            data_hash: data.utxo_data.as_ref().map(|p| p.data_hash),
            utxo_data: data.utxo_data.as_ref().map(|p| p.data.clone()),
            ring_program_id: None,
            ring_data_hash: None,
            ring_data: None,
            memo: None,
        },
    }
}

#[track_caller]
pub fn assert_indexed_deposit_utxo(
    indexed: &EncryptedUtxoMatch,
    tag: [u8; 32],
    signature: Signature,
    tree: &Pubkey,
    event: &DepositOutput,
) {
    assert_eq!(indexed.output_slot.view_tag, tag, "indexed view tag");
    assert_eq!(indexed.tx_signature, signature, "indexed signature");
    assert_eq!(
        indexed.output_slot.output_context.hash, event.utxo_hash,
        "indexed UTXO hash"
    );
    assert_eq!(
        indexed.output_slot.output_context.tree,
        to_address(tree),
        "indexed output tree"
    );
    assert_eq!(
        indexed.output_slot.output_context.leaf_index, event.leaf_index,
        "indexed leaf index"
    );
}

#[track_caller]
pub fn fetch_state<T: bytemuck::Pod, R: Rpc>(rpc: &R, pubkey: &Pubkey) -> Result<T, ClientError> {
    let account = rpc
        .get_account(to_address(pubkey))?
        .expect("account exists");
    assert_eq!(
        account.data.len(),
        core::mem::size_of::<T>(),
        "account length"
    );
    Ok(*bytemuck::from_bytes::<T>(&account.data))
}

#[track_caller]
pub fn fetch_account<R: Rpc>(rpc: &R, pubkey: &Pubkey) -> Result<Account, ClientError> {
    Ok(rpc
        .get_account(to_address(pubkey))?
        .expect("account exists"))
}

pub fn fetch_optional_account<R: Rpc>(
    rpc: &R,
    pubkey: &Pubkey,
) -> Result<Option<Account>, ClientError> {
    rpc.get_account(to_address(pubkey))
}

/// Read the runtime's confirmed transaction metadata and pin a proof-bearing
/// transaction to an explicit compute-unit ceiling.
#[track_caller]
pub fn assert_transaction_compute_units(
    rpc: &SolanaRpc,
    signature: &Signature,
    label: &str,
    limit: u64,
) -> Result<u64, ClientError> {
    let transaction = rpc.fetch_confirmed_transaction(signature)?;
    let meta = transaction.transaction.meta.ok_or_else(|| {
        ClientError::Rpc(format!("{label}: confirmed transaction has no metadata"))
    })?;
    let consumed = meta
        .compute_units_consumed
        .expect("confirmed transaction metadata must include compute units");
    assert!(
        consumed <= limit,
        "{label} consumed {consumed} CU (limit {limit})"
    );
    println!("{label}: {consumed} CU (limit {limit})");
    Ok(consumed)
}

/// Verify rollback after a rejected transaction by comparing the complete
/// account, including lamports, owner, flags, rent epoch, and data.
#[track_caller]
pub fn assert_account_unchanged<R: Rpc>(
    rpc: &R,
    pubkey: &Pubkey,
    before: &Account,
) -> Result<(), ClientError> {
    let after = fetch_account(rpc, pubkey)?;
    assert_eq!(&after, before, "account {pubkey} changed after rejection");
    Ok(())
}

/// Verify that an account remains byte-for-byte identical or remains absent.
#[track_caller]
pub fn assert_optional_account_unchanged<R: Rpc>(
    rpc: &R,
    pubkey: &Pubkey,
    before: &Option<Account>,
) -> Result<(), ClientError> {
    let after = fetch_optional_account(rpc, pubkey)?;
    assert_eq!(&after, before, "account {pubkey} changed after rejection");
    Ok(())
}

#[track_caller]
pub fn state_root_from(account: &Account) -> [u8; 32] {
    let offset = state_root_offset();
    let slice = account
        .data
        .get(offset..offset + 32)
        .expect("state root slice");
    let mut root = [0u8; 32];
    root.copy_from_slice(slice);
    root
}

/// The tree's `next_index` (leaf count). It sits immediately before the state
/// root in the tree layout (`root` is 8 bytes into the utxo layout, right after
/// the 8-byte `next_index`), so it lives at `state_root_offset() - 8`.
#[track_caller]
pub fn tree_next_index(account: &Account) -> u64 {
    let offset = state_root_offset() - 8;
    let bytes = account
        .data
        .get(offset..offset + 8)
        .expect("next index slice")
        .try_into()
        .expect("next index is 8 bytes");
    u64::from_le_bytes(bytes)
}

#[track_caller]
pub fn token_amount(account: &Account) -> u64 {
    let bytes = account
        .data
        .get(TOKEN_ACCOUNT_AMOUNT_OFFSET..TOKEN_ACCOUNT_AMOUNT_END)
        .expect("token amount slice")
        .try_into()
        .expect("token amount is 8 bytes");
    u64::from_le_bytes(bytes)
}

#[track_caller]
fn wait_for<T>(label: &str, mut poll: impl FnMut() -> Result<Option<T>, ClientError>) -> T {
    let started = Instant::now();
    let mut last_error = None;
    while started.elapsed() < INDEXER_TIMEOUT {
        match poll() {
            Ok(Some(value)) => return value,
            Ok(None) => {}
            Err(error) => last_error = Some(error.to_string()),
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    panic!(
        "timed out waiting for {label}; last indexer error: {}",
        last_error.unwrap_or_else(|| "none".to_string())
    );
}

#[track_caller]
pub fn wait_for_indexed_utxo<I: Rpc>(
    indexer: &I,
    tag: [u8; 32],
    signature: solana_signature::Signature,
) -> EncryptedUtxoMatch {
    let label = format!("indexed UTXO for signature {signature} tag {tag:?}");
    wait_for(&label, || {
        let mut cursor = None;
        loop {
            let response = indexer.get_encrypted_utxos_by_tags(
                vec![tag],
                cursor,
                Some(TAG_PAGE_LIMIT),
                None,
            )?;
            if let Some(item) = response
                .matches
                .into_iter()
                .find(|item| item.tx_signature == signature)
            {
                return Ok(Some(item));
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                return Ok(None);
            }
        }
    })
}

#[track_caller]
pub fn wait_for_merkle_proof<I: Rpc>(indexer: &I, tree: Address, leaf: [u8; 32]) -> MerkleProof {
    wait_for("indexed merkle proof", || {
        let response = indexer.get_merkle_proofs(tree, vec![leaf], None)?;
        Ok(response.proofs.into_iter().next())
    })
}

#[track_caller]
pub fn wait_for_non_inclusion_proof<I: Rpc>(
    indexer: &I,
    tree: Address,
    leaf: [u8; 32],
) -> NonInclusionProof {
    wait_for("indexed non-inclusion proof", || {
        let response = indexer.get_non_inclusion_proofs(tree, vec![leaf], None)?;
        Ok(response.proofs.into_iter().next())
    })
}

/// Wait until `leaf` is present in the nullifier tree: photon stops serving a
/// non-inclusion proof for it (the proof is consumed when the leaf is inserted).
/// Used to assert spent inputs are nullified after a transact/merge.
#[track_caller]
pub fn wait_for_nullifier_present<I: Rpc>(indexer: &I, tree: Address, leaf: [u8; 32]) {
    wait_for("nullifier present in tree", || {
        match indexer.get_non_inclusion_proofs(tree, vec![leaf], None) {
            // Photon refuses a non-inclusion proof for a nullifier that is
            // used or queued ("Nullifier leaf .. is already used or queued",
            // get_non_inclusion_proofs.rs). That specific refusal is the
            // positive signal. Any other error (transport, indexer restart)
            // retries until the deadline instead of silently counting as
            // success, and both non-terminal states surface as the "last
            // indexer error" on timeout.
            Err(error) if format!("{error:?}").contains("already used or queued") => Ok(Some(())),
            Ok(response) if response.proofs.is_empty() => Ok(Some(())),
            Ok(response) => Err(ClientError::Rpc(format!(
                "non-inclusion proof still served ({} proofs)",
                response.proofs.len()
            ))),
            Err(error) => Err(error),
        }
    });
}

#[track_caller]
pub fn wait_for_indexed_transaction<I: Rpc>(
    indexer: &I,
    tag: [u8; 32],
    signature: solana_signature::Signature,
) -> ShieldedTransaction {
    let label = format!("indexed transaction for signature {signature} tag {tag:?}");
    wait_for(&label, || {
        let mut cursor = None;
        loop {
            let response = indexer.get_shielded_transactions_by_tags(
                vec![tag],
                cursor,
                Some(TAG_PAGE_LIMIT),
                None,
            )?;
            if let Some(item) = response
                .transactions
                .into_iter()
                .find(|item| item.tx_signature == signature)
            {
                return Ok(Some(item));
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                return Ok(None);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use solana_instruction_error::InstructionError;
    use solana_transaction_error::TransactionError;
    use zolana_client::ClientError;
    use zolana_interface::error::ShieldedPoolError;
    use zolana_program_test::Rejection;

    #[test]
    fn rejection_assert_client_matches_code_and_instruction_index() {
        let source = solana_rpc_client_api::client_error::Error::from(
            TransactionError::InstructionError(2, InstructionError::Custom(7_008)),
        );
        let error = ClientError::SolanaRpcTransaction {
            operation: "test",
            source,
        };
        Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
            .at(2)
            .assert_client(&error);
    }
}
