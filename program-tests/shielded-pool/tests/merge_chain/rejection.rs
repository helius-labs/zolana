//! Guards `merge_chain_transact` applies before any pairing, so none of these
//! need a chain proving key.
//!
//! The level shape is attacker-controlled and names the outer verifying key, so
//! an unlisted shape must be refused rather than verified against some other
//! key. The nullifier queue is the only thing standing between a chain and a
//! double spend across its legs, because a leg's inputs are private to the
//! proof once they are chained.

use borsh::BorshSerialize;
use shielded_pool_tests::support::fixtures::Pool;
use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            merge_chain_transact::MergeChainTransactIxData, merge_transact::MergeProof,
        },
        MergeChainTransact,
    },
    verifying_keys::{
        merge_chain::{merge_chain_legs, merge_chain_tree_inputs},
        Bsb22Commitment,
    },
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::transact::fe;
use zolana_user_registry_interface::{
    state::{UserRecord, NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN},
    user_record_pda, USER_REGISTRY_PROGRAM_ID,
};

/// Wire-valid chain data with a zeroed proof: every vector matches the level
/// shape and every nullifier is distinct, so parsing and the tree writes
/// succeed and only the check under test can fail.
fn chain_ix_data(levels: &[u8]) -> MergeChainTransactIxData {
    let legs = merge_chain_legs(levels).expect("closed tree");
    let tree_inputs = merge_chain_tree_inputs(legs);
    MergeChainTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        bsb22_commitment: Bsb22Commitment {
            commitment: [0u8; 32],
            commitment_pok: [0u8; 32],
        },
        output_utxo_hash: fe(41),
        eddsa_owner: true,
        levels: levels.to_vec(),
        private_tx_hashes: (0..legs as u64).map(fe).collect(),
        nullifiers: (1..=tree_inputs as u64).map(fe).collect(),
        utxo_tree_root_index: vec![0; tree_inputs],
        nullifier_tree_root_index: vec![0; tree_inputs],
    }
}

/// Materialize a registry-owned `UserRecord` account directly in LiteSVM. The
/// chain instruction only reads the record.
fn write_user_record(rpc: &mut ZolanaProgramTest, owner: Pubkey) -> Pubkey {
    let mut viewing_pubkey = [7u8; P256_PUBKEY_LEN];
    if let Some(first) = viewing_pubkey.first_mut() {
        *first = 0x02;
    }
    let (address, bump) = user_record_pda(&owner);
    let record = UserRecord {
        owner: solana_address::Address::new_from_array(owner.to_bytes()),
        bump,
        owner_p256: None,
        nullifier_pubkey: [11u8; NULLIFIER_PUBKEY_LEN],
        viewing_pubkey,
        merging_enabled: true,
    };
    let mut data = vec![UserRecord::DISCRIMINATOR];
    record.serialize(&mut data).expect("serialize user record");
    data.resize(UserRecord::SIZE, 0);
    rpc.svm
        .set_account(
            address,
            Account {
                lamports: 1_000_000_000,
                data,
                owner: Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write user record");
    address
}

fn chain_env() -> (ZolanaProgramTest, Keypair, Pubkey) {
    let Pool { mut rpc, tree, .. } = Pool::initialized();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer);
    (rpc, tree, record)
}

#[track_caller]
fn expect_rejection(
    rpc: &mut ZolanaProgramTest,
    tree: &Keypair,
    record: Pubkey,
    data: MergeChainTransactIxData,
    expected: ShieldedPoolError,
) {
    let ix = MergeChainTransact {
        input_tree: tree.pubkey(),
        output_tree: tree.pubkey(),
        payer: rpc.payer.pubkey(),
        user_record: record,
        data,
    }
    .instruction();
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let error = rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect_err("guarded merge chain must be rejected");
    Rejection::pool(expected).at(1).assert_litesvm(error);
}

/// A shape with no generated outer key must be refused, not settled against
/// another shape's key.
#[test]
fn merge_chain_rejects_an_unsupported_level_shape() {
    let (mut rpc, tree, record) = chain_env();
    expect_rejection(
        &mut rpc,
        &tree,
        record,
        chain_ix_data(&[3, 1]),
        ShieldedPoolError::UnsupportedMergeChainShape,
    );
}

/// A tree that does not close is refused while the instruction data is parsed,
/// before any account is read.
#[test]
fn merge_chain_rejects_a_level_shape_that_does_not_close() {
    let (mut rpc, tree, record) = chain_env();
    let mut data = chain_ix_data(&[1, 1]);
    data.levels = vec![2, 2];
    expect_rejection(
        &mut rpc,
        &tree,
        record,
        data,
        ShieldedPoolError::InvalidMergeShape,
    );
}

/// The published nullifiers of a chain span every leg, so one UTXO spent in two
/// legs shows up as a repeat in a single queue insertion run.
#[test]
fn merge_chain_rejects_a_nullifier_spent_twice_across_legs() {
    let (mut rpc, tree, record) = chain_env();
    let mut data = chain_ix_data(&[1, 1]);
    // Slot 0 of the bottom leg, repeated as slot 0 of the top leg.
    let repeated = data.nullifiers[0];
    data.nullifiers[8] = repeated;
    expect_rejection(
        &mut rpc,
        &tree,
        record,
        data,
        ShieldedPoolError::NullifierTreeUpdateFailed,
    );
}
