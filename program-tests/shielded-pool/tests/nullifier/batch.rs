use shielded_pool_tests::support::fixtures::Pool;

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{error::ShieldedPoolError, instruction::BatchUpdateNullifierTree};
use zolana_program_test::{Rejection, ZolanaProgramTest};

// On-chain negatives against the real SBF program: the forester-authority,
// instruction-data, and protocol-config gates of `batch_update_nullifier_tree`
// each pinned to their exact error.

fn forester_env() -> (ZolanaProgramTest, Keypair, Keypair) {
    let Pool {
        rpc,
        authority,
        tree,
    } = Pool::initialized();
    (rpc, authority, tree)
}

fn batch_update_instruction(authority: Pubkey, tree: Pubkey) -> solana_instruction::Instruction {
    BatchUpdateNullifierTree {
        authority,
        tree,
        reimbursement_recipient: authority,
        new_root: [1u8; 32],
        old_root: [2u8; 32],
        zkp_batch_index: 0,
        compressed_proof_a: [0u8; 32],
        compressed_proof_b: [0u8; 64],
        compressed_proof_c: [0u8; 32],
    }
    .instruction()
}

#[test]
fn batch_update_rejects_a_non_forester_authority() {
    let (mut rpc, _authority, tree) = forester_env();
    let intruder = Keypair::new();
    rpc.airdrop(&intruder.pubkey(), 1_000_000_000)
        .expect("fund intruder");
    let tree_before = rpc.account_data(&tree.pubkey()).expect("tree data");

    let ix = batch_update_instruction(intruder.pubkey(), tree.pubkey());
    let error = rpc
        .create_and_send_transaction(&[ix], &intruder.pubkey(), &[&intruder])
        .expect_err("a signer that is not the forester authority must be rejected");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    assert_eq!(
        rpc.account_data(&tree.pubkey()).expect("tree data"),
        tree_before,
        "rejected batch update must leave the tree untouched"
    );
}

#[test]
fn batch_update_rejects_malformed_instruction_data() {
    let (mut rpc, authority, tree) = forester_env();

    let mut ix = batch_update_instruction(authority.pubkey(), tree.pubkey());
    ix.data.truncate(4);
    let error = rpc
        .create_and_send_transaction(&[ix], &authority.pubkey(), &[&authority])
        .expect_err("truncated batch-update data must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(error);
}

#[test]
fn batch_update_rejects_an_unsigned_authority() {
    let (mut rpc, authority, tree) = forester_env();

    // The correct forester authority address, but its meta carries no signature.
    let mut ix = batch_update_instruction(authority.pubkey(), tree.pubkey());
    ix.accounts.first_mut().expect("authority meta").is_signer = false;
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("an unsigned forester authority must be rejected");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(error);
}

/// A batch proof the tree cannot accept (no zkp batch is ready, or the zkp
/// batch index is out of range) must fail with the exact tree-update error and
/// leave every account untouched. Rejecting a tampered proof for a FULL zkp
/// batch is exercised on localnet only: filling one batch takes 250 queued
/// nullifiers plus a real batch-address-append proof.
#[test]
fn batch_update_rejects_a_proof_for_an_unready_zkp_batch() {
    let (mut rpc, authority, tree) = forester_env();
    let tree_before = rpc.account_data(&tree.pubkey()).expect("tree data");

    // Nothing is queued, so zkp batch 0 has no finalized hash chain.
    let ix = batch_update_instruction(authority.pubkey(), tree.pubkey());
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&authority])
        .expect_err("a proof for an unready zkp batch must be rejected");
    // Retriable. The forester resends once the hash chain finalizes.
    Rejection::pool(ShieldedPoolError::NullifierBatchNotReady).assert_litesvm(error);
    assert_eq!(
        rpc.account_data(&tree.pubkey()).expect("tree data"),
        tree_before,
        "rejected batch update must leave the tree untouched"
    );
    // Failing-path frame: no message account other than the fee payer changed.
    rpc.last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[rpc.payer.pubkey()]);

    // An out-of-range zkp batch index is a malformed request, not a retriable one.
    let out_of_range = BatchUpdateNullifierTree {
        authority: authority.pubkey(),
        tree: tree.pubkey(),
        reimbursement_recipient: authority.pubkey(),
        new_root: [1u8; 32],
        old_root: [2u8; 32],
        zkp_batch_index: u16::MAX,
        compressed_proof_a: [0u8; 32],
        compressed_proof_b: [0u8; 64],
        compressed_proof_c: [0u8; 32],
    }
    .instruction();
    let error = rpc
        .create_and_send_default_payer_transaction(&[out_of_range], &[&authority])
        .expect_err("an out-of-range zkp batch index must be rejected");
    Rejection::pool(ShieldedPoolError::NullifierTreeUpdateFailed).assert_litesvm(error);
    assert_eq!(
        rpc.account_data(&tree.pubkey()).expect("tree data"),
        tree_before,
        "rejected batch update must leave the tree untouched"
    );
    rpc.last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[rpc.payer.pubkey()]);
}

#[test]
fn batch_update_rejects_a_paused_tree() {
    let (mut rpc, authority, tree) = forester_env();
    rpc.pause_tree(&authority, &tree, true).expect("pause tree");

    let ix = batch_update_instruction(authority.pubkey(), tree.pubkey());
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&authority])
        .expect_err("batch update on a paused tree must be rejected");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(error);
}

#[test]
fn batch_update_rejects_a_non_config_account() {
    let (mut rpc, authority, tree) = forester_env();
    let impostor = Pubkey::new_unique();
    rpc.airdrop(&impostor, 1_000_000).expect("fund impostor");

    let mut ix = batch_update_instruction(authority.pubkey(), tree.pubkey());
    ix.accounts.get_mut(1).expect("protocol config meta").pubkey = impostor;
    let error = rpc
        .create_and_send_transaction(&[ix], &authority.pubkey(), &[&authority])
        .expect_err("a non-config account in the config slot must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidProtocolConfig).assert_litesvm(error);
}
