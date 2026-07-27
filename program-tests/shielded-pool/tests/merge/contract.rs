use shielded_pool_tests::support::{fixtures::Pool, transact::write_zone_config_account};

use borsh::BorshSerialize;
use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::merge_transact::{MergeProof, MergeTransactIxData, MERGE_INPUT_COUNT},
        MergeTransact, MergeZone,
    },
    state::{discriminator::ZONE_CONFIG, ZoneConfig},
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::state_model::{
    Action, ExecutionRail, ModelBackend, ModelError, ShieldedPoolBackend,
};
use zolana_test_utils::transact::fe;
use zolana_user_registry_interface::{
    state::{UserRecord, NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN},
    USER_REGISTRY_PROGRAM_ID,
};

#[test]
fn merge_covers_every_supported_input_count() {
    for count in 1usize..=8 {
        let mut backend = ModelBackend::new(9);
        backend
            .apply(&Action::SetMergePermission {
                authority: 9,
                actor: 1,
                enabled: true,
            })
            .unwrap();
        for amount in 1..=count as u64 {
            backend
                .apply(&Action::Deposit {
                    actor: 1,
                    asset: 0,
                    amount,
                })
                .unwrap();
        }
        let expected: u64 = (1..=count as u64).sum();
        backend
            .apply(&Action::Consolidate {
                actor: 1,
                asset: 0,
                max_inputs: count,
                expiry: u64::MAX,
                nonce: count as u64,
                rail: ExecutionRail::P256 { owner: 1 },
            })
            .unwrap();
        assert_eq!(backend.state.balance(1, 0), expected);
        assert_eq!(backend.state.spendable_utxos(1, 0), 1);
    }
}

#[test]
fn merge_requires_opt_in_and_rolls_back_on_rejection() {
    let mut backend = ModelBackend::new(9);
    backend
        .apply(&Action::Deposit {
            actor: 1,
            asset: 0,
            amount: 10,
        })
        .unwrap();
    assert_eq!(
        backend.apply(&Action::Consolidate {
            actor: 1,
            asset: 0,
            max_inputs: 8,
            expiry: u64::MAX,
            nonce: 1,
            rail: ExecutionRail::Eddsa { signer: 1 },
        }),
        Err(ModelError::MergeDisabled)
    );
}

/// Wire-valid default-rail merge data with a zeroed proof: eight distinct
/// nullifiers against root-history slot 0, so every parse and tree step
/// succeeds and only the checks under test can fail. The merge output is
/// ciphertext-free (recovered from the first input and its nullifier).
fn merge_ix_data(eddsa_owner: bool) -> MergeTransactIxData {
    MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: fe(41),
        eddsa_owner,
        private_tx_hash: [0u8; 32],
        nullifiers: (1..=MERGE_INPUT_COUNT as u64).map(fe).collect(),
        utxo_tree_root_index: vec![0; MERGE_INPUT_COUNT],
        nullifier_tree_root_index: vec![0; MERGE_INPUT_COUNT],
    }
}

/// Materialize a registry-owned `UserRecord` account directly in LiteSVM. The
/// merge instruction only reads the record, so fabricating it exercises the
/// same validation as a record created through the registry program.
fn write_user_record(
    rpc: &mut ZolanaProgramTest,
    owner: Pubkey,
    owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    merging_enabled: bool,
) -> Pubkey {
    // Compressed-point prefix 0x02 keeps `pk_field(viewing_pubkey)` computable.
    let mut viewing_pubkey = [7u8; P256_PUBKEY_LEN];
    if let Some(first) = viewing_pubkey.first_mut() {
        *first = 0x02;
    }
    let record = UserRecord {
        owner,
        bump: 0,
        owner_p256,
        nullifier_pubkey: [11u8; NULLIFIER_PUBKEY_LEN],
        viewing_pubkey,
        sync_delegate: None,
        entries: Vec::new(),
        merging_enabled,
    };
    let mut data = vec![UserRecord::DISCRIMINATOR];
    record
        .serialize(&mut data)
        .expect("serialize fabricated user record");
    let address = Pubkey::new_unique();
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
        .expect("write fabricated user record");
    address
}

fn merge_env() -> (ZolanaProgramTest, Keypair) {
    let Pool { rpc, tree, .. } = Pool::initialized();
    (rpc, tree)
}

fn merge_instruction(
    rpc: &ZolanaProgramTest,
    tree: &Keypair,
    user_record: Pubkey,
    data: MergeTransactIxData,
) -> solana_instruction::Instruction {
    MergeTransact {
        input_tree: tree.pubkey(),
        output_tree: tree.pubkey(),
        payer: rpc.payer.pubkey(),
        user_record,
        data,
    }
    .instruction()
}

#[test]
fn merge_rejects_a_user_record_not_owned_by_the_registry() {
    let (mut rpc, tree) = merge_env();
    // A funded system-owned account standing in for the record.
    let impostor = Pubkey::new_unique();
    rpc.airdrop(&impostor, 1_000_000).expect("fund impostor");
    let tree_before = rpc.account_data(&tree.pubkey()).expect("tree data");

    let ix = merge_instruction(&rpc, &tree, impostor, merge_ix_data(true));
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a non-registry record account must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidUserRecord).assert_litesvm(error);
    assert_eq!(
        rpc.account_data(&tree.pubkey()).expect("tree data"),
        tree_before,
        "rejected merge must leave the tree untouched"
    );
}

#[test]
fn merge_rejects_a_malformed_user_record() {
    let (mut rpc, tree) = merge_env();
    // Registry-owned, but the body is garbage: the discriminator is wrong and
    // the borsh decode cannot succeed.
    let record = Pubkey::new_unique();
    rpc.svm
        .set_account(
            record,
            Account {
                lamports: 1_000_000_000,
                data: vec![0xAA; 16],
                owner: Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write malformed record");

    let ix = merge_instruction(&rpc, &tree, record, merge_ix_data(true));
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a malformed user record must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidUserRecord).assert_litesvm(error);
}

#[test]
fn merge_rejects_a_p256_rail_without_a_registered_p256_owner() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    // Valid record, merging enabled, but no P256 owner registered while the
    // instruction selects the P256 rail.
    let record = write_user_record(&mut rpc, payer, None, true);

    let ix = merge_instruction(&rpc, &tree, record, merge_ix_data(false));
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a P256 merge without a registered P256 owner must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidUserRecord).assert_litesvm(error);
}

#[test]
fn merge_rejects_a_wrong_input_count_shape() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    // Seven nullifiers serialize fine but violate the fixed 8-in/1-out merge
    // shape at parse time.
    let mut data = merge_ix_data(true);
    data.nullifiers.pop();
    let ix = merge_instruction(&rpc, &tree, record, data);
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a 7-input merge must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidMergeShape).assert_litesvm(error);
}

#[test]
fn merge_rejects_an_expired_transaction() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    // The merge dispatch has its own expiry gate, distinct from transact's.
    // Pin the sysvar clock one second past the instruction's expiry.
    let mut data = merge_ix_data(true);
    data.expiry_unix_ts = 1_000;
    let mut clock = rpc.svm.get_sysvar::<solana_clock::Clock>();
    clock.unix_timestamp = 1_001;
    rpc.svm.set_sysvar(&clock);
    let ix = merge_instruction(&rpc, &tree, record, data);
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("an expired merge must be rejected");
    Rejection::pool(ShieldedPoolError::ExpiredTransaction).assert_litesvm(error);
}

#[test]
fn merge_rejects_a_negative_clock() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    // A negative clock must reject regardless of `expiry_unix_ts` (here the
    // maximal one), before the `as u64` comparison could wrap it around.
    let data = merge_ix_data(true);
    let mut clock = rpc.svm.get_sysvar::<solana_clock::Clock>();
    clock.unix_timestamp = -1;
    rpc.svm.set_sysvar(&clock);
    let ix = merge_instruction(&rpc, &tree, record, data);
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a merge under a negative clock must be rejected");
    Rejection::pool(ShieldedPoolError::ExpiredTransaction).assert_litesvm(error);
}

#[test]
fn merge_rejects_a_non_writable_tree() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    let mut ix = merge_instruction(&rpc, &tree, record, merge_ix_data(true));
    // input_tree and output_tree are duplicate metas of one account; the
    // runtime unions their privileges, so both must be downgraded.
    ix.accounts.first_mut().expect("input tree meta").is_writable = false;
    ix.accounts
        .get_mut(1)
        .expect("output tree meta")
        .is_writable = false;
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a read-only tree must be rejected");
    Rejection::custom(u32::from(
        zolana_account_checks::AccountError::AccountNotMutable,
    ))
    .assert_litesvm(error);
}

#[test]
fn merge_rejects_an_unsigned_payer() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    // The instruction payer differs from the transaction fee payer and never
    // signs; the payer signer check is the only authorization on merge.
    let outsider = Pubkey::new_unique();
    let mut ix = MergeTransact {
        input_tree: tree.pubkey(),
        output_tree: tree.pubkey(),
        payer: outsider,
        user_record: record,
        data: merge_ix_data(true),
    }
    .instruction();
    ix.accounts.get_mut(2).expect("payer meta").is_signer = false;
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("an unsigned payer must be rejected");
    Rejection::custom(u32::from(
        zolana_account_checks::AccountError::InvalidSigner,
    ))
    .assert_litesvm(error);
}

#[test]
fn merge_zone_rejects_an_unsigned_zone_config() {
    let (mut rpc, tree) = merge_env();
    let mut ix = zolana_interface::instruction::MergeZone {
        input_tree: tree.pubkey(),
        output_tree: tree.pubkey(),
        zone_program_id: Pubkey::new_from_array(zolana_program_test::ZONE_TEST_PROGRAM_ID),
        payer: rpc.payer.pubkey(),
        data: merge_ix_data(true),
        output_zone_data_hash: fe(99),
    }
    .cpi_instruction();
    // The `zone_config` signature IS the zone authorization; without the zone
    // program's `invoke_signed` the flag must be rejected before the config is
    // even loaded.
    ix.accounts.get_mut(2).expect("zone config meta").is_signer = false;

    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned zone config must be rejected");
    Rejection::custom(u32::from(
        zolana_account_checks::AccountError::InvalidSigner,
    ))
    .assert_litesvm(error);
}

#[test]
fn merge_rejects_a_paused_tree() {
    let Pool {
        mut rpc,
        authority,
        tree,
    } = Pool::initialized();
    rpc.pause_tree(&authority, &tree, true).expect("pause tree");
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);

    let ix = merge_instruction(&rpc, &tree, record, merge_ix_data(true));
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a merge against a paused tree must be rejected");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(error);
}

#[test]
fn default_rail_merge_rejects_a_zeroed_proof_exactly() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    // Fully valid record and wire-valid merge data; the zeroed proof is the
    // only defect, so the failure is proof verification on the default
    // (registry-bound) rail.
    let record = write_user_record(&mut rpc, payer, None, true);
    let tree_before = rpc.account_data(&tree.pubkey()).expect("tree data");

    let ix = merge_instruction(&rpc, &tree, record, merge_ix_data(true));
    // Proof verification needs more than the 200k default budget.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let error = rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect_err("a zeroed default-rail merge proof must be rejected");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
        .at(1)
        .assert_litesvm(error);
    assert_eq!(
        rpc.account_data(&tree.pubkey()).expect("tree data"),
        tree_before,
        "rejected merge must roll back the nullifier and output inserts"
    );
}

#[test]
fn default_rail_merge_rejects_undecompressable_proof_points_exactly() {
    let (mut rpc, tree) = merge_env();
    let payer = rpc.payer.pubkey();
    let record = write_user_record(&mut rpc, payer, None, true);
    let tree_before = rpc.account_data(&tree.pubkey()).expect("tree data");

    // 0xFF-filled points carry invalid compression flag bits, so the verifier
    // fails at G1/G2 decompression -- the 7007 encoding error, distinct from
    // the 7008 pairing failure of a well-formed but non-verifying proof.
    let mut data = merge_ix_data(true);
    data.proof = MergeProof {
        a: [0xFF; 32],
        b: [0xFF; 64],
        c: [0xFF; 32],
    };
    let ix = merge_instruction(&rpc, &tree, record, data);
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let error = rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect_err("undecompressable merge proof points must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidTransactProofEncoding)
        .at(1)
        .assert_litesvm(error);
    assert_eq!(
        rpc.account_data(&tree.pubkey()).expect("tree data"),
        tree_before,
        "rejected merge must roll back the nullifier and output inserts"
    );
}

/// SPP-shaped zone merge instruction (as a zone program would CPI it, the
/// canonical `zone_auth` PDA marked signer).
fn merge_zone_cpi_instruction(
    rpc: &ZolanaProgramTest,
    tree: &Keypair,
    data: MergeTransactIxData,
    output_zone_data_hash: [u8; 32],
) -> solana_instruction::Instruction {
    MergeZone {
        input_tree: tree.pubkey(),
        output_tree: tree.pubkey(),
        zone_program_id: Pubkey::new_from_array(zolana_program_test::ZONE_TEST_PROGRAM_ID),
        payer: rpc.payer.pubkey(),
        data,
        output_zone_data_hash,
    }
    .cpi_instruction()
}

/// A valid-shaped `ZoneConfig` account written at a keypair address, so the
/// "zone_config" can sign a LiteSVM transaction without a zone program CPI.
/// Only the owner + size + discriminator checks apply (INV-XC-26); the stored
/// fields are never validated against a derivation.
fn write_fake_zone_config(rpc: &mut ZolanaProgramTest, address: Pubkey, discriminator: u8) {
    let mut data = vec![0u8; ZoneConfig::SIZE];
    if let Some(first) = data.first_mut() {
        *first = discriminator;
    }
    write_zone_config_account(rpc, address, rpc.program_id, data);
}

#[test]
fn merge_zone_rejects_a_zone_config_with_a_wrong_owner() {
    let (mut rpc, tree) = merge_env();
    // A signing account that is system-owned instead of SPP-owned.
    let impostor = Keypair::new();
    rpc.airdrop(&impostor.pubkey(), 1_000_000)
        .expect("fund impostor");

    let mut ix = merge_zone_cpi_instruction(&rpc, &tree, merge_ix_data(true), fe(90));
    ix.accounts.get_mut(2).expect("zone config meta").pubkey = impostor.pubkey();
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&impostor])
        .expect_err("a zone config with a wrong owner must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidZoneConfig).assert_litesvm(error);
}

#[test]
fn merge_zone_rejects_a_zone_config_with_a_wrong_discriminator() {
    let (mut rpc, tree) = merge_env();
    // SPP-owned and correctly sized, but the discriminator byte is wrong.
    let fake = Keypair::new();
    write_fake_zone_config(&mut rpc, fake.pubkey(), ZONE_CONFIG + 1);

    let mut ix = merge_zone_cpi_instruction(&rpc, &tree, merge_ix_data(true), fe(91));
    ix.accounts.get_mut(2).expect("zone config meta").pubkey = fake.pubkey();
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&fake])
        .expect_err("a zone config with a wrong discriminator must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidZoneConfig).assert_litesvm(error);
}

#[test]
fn merge_zone_rejects_an_unsigned_payer() {
    let (mut rpc, tree) = merge_env();
    // Valid signed zone config, so the payer signer check (third account) is
    // the branch that fires.
    let zone_config_signer = Keypair::new();
    write_fake_zone_config(&mut rpc, zone_config_signer.pubkey(), ZONE_CONFIG);

    let outsider = Pubkey::new_unique();
    let mut ix = MergeZone {
        input_tree: tree.pubkey(),
        output_tree: tree.pubkey(),
        zone_program_id: Pubkey::new_from_array(zolana_program_test::ZONE_TEST_PROGRAM_ID),
        payer: outsider,
        data: merge_ix_data(true),
        output_zone_data_hash: fe(92),
    }
    .cpi_instruction();
    ix.accounts.get_mut(2).expect("zone config meta").pubkey = zone_config_signer.pubkey();
    ix.accounts.get_mut(3).expect("payer meta").is_signer = false;
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&zone_config_signer])
        .expect_err("an unsigned zone merge payer must be rejected");
    Rejection::custom(u32::from(
        zolana_account_checks::AccountError::InvalidSigner,
    ))
    .assert_litesvm(error);
}

#[test]
fn merge_zone_rejects_a_wrong_input_count_shape_exactly() {
    let (mut rpc, tree) = merge_env();
    // Seven nullifiers violate the fixed 8-in/1-out shape at parse time, which
    // runs before any account (or the zone_config signature) is checked.
    let mut data = merge_ix_data(true);
    data.nullifiers.pop();
    let mut ix = merge_zone_cpi_instruction(&rpc, &tree, data, fe(93));
    ix.accounts.get_mut(2).expect("zone config meta").is_signer = false;
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a 7-input zone merge must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidMergeShape).assert_litesvm(error);
}

#[test]
fn merge_zone_rejects_a_paused_tree() {
    let Pool {
        mut rpc,
        authority,
        tree,
    } = Pool::initialized();
    rpc.load_zone_test_program()
        .expect("load zone test program");
    rpc.create_zone_config(&authority, &authority.pubkey(), true)
        .expect("create zone config");
    rpc.pause_tree(&authority, &tree, true).expect("pause tree");

    // Through the zone test program so the real `zone_auth` PDA signs; every
    // wire field is valid and the pause alone must halt the tree mutation.
    let ix = MergeZone {
        input_tree: tree.pubkey(),
        output_tree: tree.pubkey(),
        zone_program_id: Pubkey::new_from_array(zolana_program_test::ZONE_TEST_PROGRAM_ID),
        payer: rpc.payer.pubkey(),
        data: merge_ix_data(true),
        output_zone_data_hash: fe(95),
    }
    .instruction();
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a zone merge against a paused tree must be rejected");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(error);
}
