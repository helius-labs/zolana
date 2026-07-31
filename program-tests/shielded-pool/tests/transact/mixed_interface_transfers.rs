//! Real-proof coverage for transactions with multiple ordered interface transfers.

#[path = "../common/setup.rs"]
mod common;
#[path = "../common/transact.rs"]
mod transact_common;

use num_bigint::BigUint;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{TransferInput, TransferOutput, STATE_TREE_HEIGHT};
use zolana_event::{general_event_from_indexed, SplTransfer};
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            InterfaceTransfer, ResolvedInterfaceTransfer, TransactIxData,
        },
        Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
        TransactSplDepositAccounts, TransactSplWithdrawalAccounts,
    },
    pda, N_PUBLIC_SLOTS, SOL_ASSET_FIELD,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{test_blinding, ZolanaProgramTest};
use zolana_transaction::{
    instructions::transact::{spp_proof_inputs::signed_to_field, PrivateTxHash},
    Data, Utxo, SOL_MINT,
};
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, inline_outputs, new_transact_ix_data, nullifier_tree,
    output_owner_pk_hashes, prove_and_verify_transfer, public_input_hash, real_output,
    set_output_owner_tags, spend_input, start_prover, transfer_output, SpendInputArgs,
    TransferProverInputsArgs,
};

const SOL_SPLIT_TOTAL: u64 = 1_000_000_000;
const SPL_SPLIT_TOTAL: u64 = 1_000;

struct TransactEnv {
    rpc: ZolanaProgramTest,
    authority: Keypair,
    tree: Keypair,
}

impl TransactEnv {
    fn boot() -> Option<Self> {
        let mut rpc = common::program_test()?;
        start_prover().expect("start prover");
        let authority = Keypair::new();
        rpc.create_protocol_config(&authority)
            .expect("create protocol config");
        let tree = rpc
            .create_tree(common::tree_account_size(), &authority)
            .expect("create tree");
        Some(Self {
            rpc,
            authority,
            tree,
        })
    }
}

struct SpendNote {
    input: TransferInput,
    dummy_input: TransferInput,
    utxo_hash: [u8; 32],
    nullifier: [u8; 32],
    dummy_nullifier: [u8; 32],
    roots: ([u8; 32], [u8; 32]),
    owner_pk_hash: [u8; 32],
    nullifier_pk: [u8; 32],
}

struct WitnessOutput {
    transfer: TransferOutput,
    hash: [u8; 32],
    private_hash: [u8; 32],
    nullifier_pk: [u8; 32],
    view_tag: [u8; 32],
}

fn on_chain_roots(rpc: &ZolanaProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

fn build_spend_note(
    env: &TransactEnv,
    utxo: Utxo,
    nullifier_key: NullifierKey,
    utxo_hash: [u8; 32],
) -> SpendNote {
    let owner_pk_hash = utxo.owner.owner_proof_input_hash().expect("owner pk hash");
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk).expect("owner field");
    let roots = on_chain_roots(&env.rpc, &env.tree.pubkey(), 1);

    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), roots.0, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();

    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), roots.1, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &utxo.blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non inclusion proof");
    let (dummy_input, dummy_nullifier) =
        dummy_input(&[2u8; 31], &nf_tree, roots).expect("dummy input");
    let input = spend_input(SpendInputArgs {
        utxo: &utxo,
        owner_field: &owner_field,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("real input");

    SpendNote {
        input,
        dummy_input,
        utxo_hash,
        nullifier,
        dummy_nullifier,
        roots,
        owner_pk_hash,
        nullifier_pk,
    }
}

fn deposit_sol_note(env: &mut TransactEnv, amount: u64) -> SpendNote {
    let payer = env.rpc.payer.insecure_clone();
    let blinding = test_blinding(7);
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer.pubkey().to_bytes()),
        asset: SOL_MINT,
        amount,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk).expect("owner field");
    let event = env
        .rpc
        .deposit_sol(&env.tree.pubkey(), &payer, amount, owner_field, blinding)
        .expect("SOL deposit");
    let zero = [0u8; 32];
    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    assert_eq!(event.utxo_hash, utxo_hash);
    build_spend_note(env, utxo, nullifier_key, utxo_hash)
}

fn deposit_spl_note(
    env: &mut TransactEnv,
    mint: Pubkey,
    amount: u64,
) -> (SpendNote, Pubkey, Pubkey) {
    deposit_spl_note_with_program(env, mint, amount, ZolanaProgramTest::token_program_id())
}

fn deposit_spl_note_with_program(
    env: &mut TransactEnv,
    mint: Pubkey,
    amount: u64,
    token_program: Pubkey,
) -> (SpendNote, Pubkey, Pubkey) {
    env.rpc
        .ensure_asset_counter(&env.authority)
        .expect("asset counter");
    let (_, vault) = env
        .rpc
        .create_spl_interface_with_program(&env.authority, &mint, token_program)
        .expect("SPL interface");
    let payer = env.rpc.payer.insecure_clone();
    let source = env
        .rpc
        .create_token_account_with_program(&mint, &payer.pubkey(), token_program)
        .expect("source token account");
    env.rpc
        .mint_to_with_program(&mint, &source, amount, token_program)
        .expect("mint tokens");

    let blinding = test_blinding(7);
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer.pubkey().to_bytes()),
        asset: Address::new_from_array(mint.to_bytes()),
        amount,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk).expect("owner field");
    let data = ZolanaProgramTest::spl_shield_data_with_program(
        amount,
        owner_field,
        blinding,
        &mint,
        &source,
        token_program,
    );
    let event = env
        .rpc
        .deposit(&env.tree.pubkey(), &payer, &data)
        .expect("SPL deposit");
    let zero = [0u8; 32];
    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    assert_eq!(event.utxo_hash, utxo_hash);
    (
        build_spend_note(env, utxo, nullifier_key, utxo_hash),
        vault,
        source,
    )
}

fn dummy_outputs(owner_tag: [u8; 32]) -> Vec<WitnessOutput> {
    [[31u8; 31], [32u8; 31], [33u8; 31]]
        .iter()
        .map(|blinding| {
            let (transfer, hash) = dummy_transfer_output(blinding).expect("dummy transfer output");
            WitnessOutput {
                transfer,
                hash,
                private_hash: [0u8; 32],
                nullifier_pk: [0u8; 32],
                view_tag: owner_tag,
            }
        })
        .collect()
}

fn real_witness_output(
    signing_pubkey: PublicKey,
    nullifier_pk: [u8; 32],
    asset: Address,
    amount: u64,
    blinding: [u8; 31],
) -> WitnessOutput {
    let output = real_output(signing_pubkey, nullifier_pk, asset, amount, blinding);
    let hash = output.hash().expect("real output hash");
    let view_tag = signing_pubkey
        .confidential_view_tag()
        .expect("confidential view tag");
    WitnessOutput {
        transfer: transfer_output(&output).expect("real transfer output"),
        hash,
        private_hash: hash,
        nullifier_pk,
        view_tag,
    }
}

fn public_slots(
    transfers: impl IntoIterator<Item = ([u8; 32], i64)>,
) -> ([[u8; 32]; N_PUBLIC_SLOTS], [[u8; 32]; N_PUBLIC_SLOTS]) {
    let mut aggregates: Vec<([u8; 32], i64)> = Vec::new();
    for (asset, amount) in transfers {
        if let Some((_, total)) = aggregates
            .iter_mut()
            .find(|(existing, _)| *existing == asset)
        {
            *total = total.checked_add(amount).expect("public amount sum");
        } else {
            aggregates.push((asset, amount));
        }
    }
    assert!(aggregates.len() <= N_PUBLIC_SLOTS);
    let mut assets = [[0u8; 32]; N_PUBLIC_SLOTS];
    let mut amounts = [[0u8; 32]; N_PUBLIC_SLOTS];
    for ((asset_slot, amount_slot), (asset, amount)) in
        assets.iter_mut().zip(amounts.iter_mut()).zip(aggregates)
    {
        *asset_slot = asset;
        *amount_slot = signed_to_field(amount);
    }
    (assets, amounts)
}

fn prove_spend(
    env: &TransactEnv,
    note: SpendNote,
    interface_transfers: Vec<InterfaceTransfer>,
    resolved_transfers: &[ResolvedInterfaceTransfer],
    public_transfers: impl IntoIterator<Item = ([u8; 32], i64)>,
    mut witness_outputs: Vec<WitnessOutput>,
) -> TransactIxData {
    assert_eq!(witness_outputs.len(), 3);
    let output_hashes: Vec<[u8; 32]> = witness_outputs.iter().map(|output| output.hash).collect();
    let output_private_hashes: Vec<[u8; 32]> = witness_outputs
        .iter()
        .map(|output| output.private_hash)
        .collect();
    let view_tags: Vec<[u8; 32]> = witness_outputs
        .iter()
        .map(|output| output.view_tag)
        .collect();
    let mut ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(note.nullifier, 1),
            eddsa_input_utxo(note.dummy_nullifier, 1),
        ],
        interface_transfers,
        inline_outputs(&output_hashes, &view_tags),
    );
    let output_owner_pk_hashes =
        output_owner_pk_hashes(&ix_data.outputs).expect("output owner pk hashes");
    let nullifier_pks: Vec<[u8; 32]> = witness_outputs
        .iter()
        .map(|output| output.nullifier_pk)
        .collect();
    let mut transfer_outputs: Vec<TransferOutput> = witness_outputs
        .drain(..)
        .map(|output| output.transfer)
        .collect();
    set_output_owner_tags(
        &mut transfer_outputs,
        &output_owner_pk_hashes,
        &nullifier_pks,
    );

    let external_hash =
        external_data_hash(&ix_data, resolved_transfers).expect("external data hash");
    let private_tx = PrivateTxHash::new(
        &[note.utxo_hash, [0u8; 32]],
        &output_private_hashes,
        &external_hash,
    )
    .hash()
    .expect("private tx hash");
    let (public_slot_assets, public_slot_amounts) = public_slots(public_transfers);
    let payer_pk_hash = zolana_hasher::primitives::hash_bytes(&env.rpc.payer.pubkey().to_bytes())
        .expect("payer pubkey hash");
    let public_hash = public_input_hash(
        &[note.nullifier, note.dummy_nullifier],
        &output_hashes,
        &[note.roots.0, note.roots.0],
        &[note.roots.1, note.roots.1],
        &private_tx,
        &external_hash,
        &public_slot_assets,
        &public_slot_amounts,
        &payer_pk_hash,
        &[note.owner_pk_hash, note.owner_pk_hash],
        &output_owner_pk_hashes,
    );
    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![note.input, note.dummy_input],
        outputs: transfer_outputs,
        external_data_hash: external_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        payer_pk_hash,
        public_input_hash: public_hash,
    });
    ix_data.proof = prove_and_verify_transfer(&prover_inputs, public_hash, "multi-leg transact")
        .expect("prove multi-leg transact");
    ix_data.private_tx_hash = private_tx;
    ix_data
}

fn sol_split_case(reorder_recipients: bool) {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };
    let payer = env.rpc.payer.insecure_clone();
    let note = deposit_sol_note(&mut env, SOL_SPLIT_TOTAL);
    let user_amount = 700_000_000u64;
    let relayer_amount = SOL_SPLIT_TOTAL - user_amount;
    let user = Keypair::new().pubkey();
    let relayer = Keypair::new().pubkey();
    env.rpc.airdrop(&user, 1_000_000).expect("airdrop user");
    env.rpc
        .airdrop(&relayer, 1_000_000)
        .expect("airdrop relayer");
    let user_before = env.rpc.svm.get_balance(&user).expect("user balance");
    let relayer_before = env.rpc.svm.get_balance(&relayer).expect("relayer balance");
    let vault = pda::sol_interface();
    let vault_before = env.rpc.svm.get_balance(&vault).unwrap_or(0);

    let interface_transfers = vec![
        InterfaceTransfer::SolWithdrawal {
            amount: user_amount,
        },
        InterfaceTransfer::SolWithdrawal {
            amount: relayer_amount,
        },
    ];
    let resolved_transfers = [
        ResolvedInterfaceTransfer::SolWithdrawal {
            amount: user_amount,
            recipient: user.to_bytes(),
        },
        ResolvedInterfaceTransfer::SolWithdrawal {
            amount: relayer_amount,
            recipient: relayer.to_bytes(),
        },
    ];
    let data = prove_spend(
        &env,
        note,
        interface_transfers,
        &resolved_transfers,
        [
            (SOL_ASSET_FIELD, -(user_amount as i64)),
            (SOL_ASSET_FIELD, -(relayer_amount as i64)),
        ],
        dummy_outputs(env.rpc.payer.pubkey().to_bytes()),
    );
    let mut ix = Transact {
        payer: payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient: user }),
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                recipient: relayer,
            }),
        ],
        data,
    }
    .instruction();

    if reorder_recipients {
        let user_position = ix
            .accounts
            .iter()
            .position(|account| account.pubkey == user)
            .expect("user account position");
        let relayer_position = ix
            .accounts
            .iter()
            .position(|account| account.pubkey == relayer)
            .expect("relayer account position");
        ix.accounts.swap(user_position, relayer_position);
        let result = env
            .rpc
            .create_and_send_default_payer_transaction(&[ix], &[]);
        assert!(result.is_err(), "reordered settlement groups must fail");
        assert_eq!(env.rpc.svm.get_balance(&user).unwrap_or(0), user_before);
        assert_eq!(
            env.rpc.svm.get_balance(&relayer).unwrap_or(0),
            relayer_before
        );
        assert_eq!(env.rpc.svm.get_balance(&vault).unwrap_or(0), vault_before);
        return;
    }

    let outcome = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect("two-recipient SOL withdrawal");
    assert_eq!(
        env.rpc.svm.get_balance(&user).unwrap_or(0),
        user_before + user_amount
    );
    assert_eq!(
        env.rpc.svm.get_balance(&relayer).unwrap_or(0),
        relayer_before + relayer_amount
    );
    assert_eq!(
        env.rpc.svm.get_balance(&vault).unwrap_or(0),
        vault_before - SOL_SPLIT_TOTAL
    );
    let event = outcome.events.first().expect("transact event");
    assert_eq!(outcome.events.len(), 1);
    let event = general_event_from_indexed(event).expect("decode transact event");
    assert_eq!(
        event.spl_transfers,
        vec![
            SplTransfer {
                is_deposit: false,
                amount: user_amount,
                asset: None,
            },
            SplTransfer {
                is_deposit: false,
                amount: relayer_amount,
                asset: None,
            },
        ]
    );
}

#[test]
fn two_sol_withdrawals_share_one_public_asset_slot() {
    sol_split_case(false);
}

#[test]
fn reordered_same_asset_account_groups_fail_closed() {
    sol_split_case(true);
}

fn repeated_same_mint_spl_withdrawals_settle(token_program: Pubkey) {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };
    let payer = env.rpc.payer.insecure_clone();
    let mint = env
        .rpc
        .create_mint_with_program(token_program)
        .expect("create mint");
    let (note, vault, _) =
        deposit_spl_note_with_program(&mut env, mint, SPL_SPLIT_TOTAL, token_program);
    let first_amount = 400u64;
    let second_amount = SPL_SPLIT_TOTAL - first_amount;
    let first_token = env
        .rpc
        .create_token_account_with_program(&mint, &payer.pubkey(), token_program)
        .expect("first recipient token account");
    let second_token = env
        .rpc
        .create_token_account_with_program(&mint, &payer.pubkey(), token_program)
        .expect("second recipient token account");
    let vault_before = env.rpc.token_balance(&vault).expect("vault balance");
    let mint_field = zolana_hasher::primitives::hash_bytes(&mint.to_bytes()).expect("mint field");
    let spl_interface_bump = pda::spl_interface_with_bump(&mint).1;
    let interface_transfers = vec![
        InterfaceTransfer::SplWithdrawal {
            amount: first_amount,
            spl_interface_bump,
        },
        InterfaceTransfer::SplWithdrawal {
            amount: second_amount,
            spl_interface_bump,
        },
    ];
    let resolved_transfers = [
        ResolvedInterfaceTransfer::SplWithdrawal {
            amount: first_amount,
            user_token_account: first_token.to_bytes(),
            spl_interface: vault.to_bytes(),
        },
        ResolvedInterfaceTransfer::SplWithdrawal {
            amount: second_amount,
            user_token_account: second_token.to_bytes(),
            spl_interface: vault.to_bytes(),
        },
    ];
    let data = prove_spend(
        &env,
        note,
        interface_transfers,
        &resolved_transfers,
        [
            (mint_field, -(first_amount as i64)),
            (mint_field, -(second_amount as i64)),
        ],
        dummy_outputs(env.rpc.payer.pubkey().to_bytes()),
    );
    let spl_transfer = |user_token_account| {
        TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
            mint,
            spl_interface: vault,
            user_token_account,
            token_program,
        })
    };
    let ix = Transact {
        payer: payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![spl_transfer(first_token), spl_transfer(second_token)],
        data,
    }
    .instruction();
    let outcome = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect("same-mint SPL split");
    assert_eq!(env.rpc.token_balance(&first_token), Some(first_amount));
    assert_eq!(env.rpc.token_balance(&second_token), Some(second_amount));
    assert_eq!(
        env.rpc.token_balance(&vault),
        Some(vault_before - SPL_SPLIT_TOTAL)
    );
    let event = outcome.events.first().expect("transact event");
    assert_eq!(outcome.events.len(), 1);
    let event = general_event_from_indexed(event).expect("decode transact event");
    assert_eq!(
        event.spl_transfers,
        vec![
            SplTransfer {
                is_deposit: false,
                amount: first_amount,
                asset: Some(mint.to_bytes()),
            },
            SplTransfer {
                is_deposit: false,
                amount: second_amount,
                asset: Some(mint.to_bytes()),
            },
        ]
    );
}

#[test]
fn repeated_same_mint_spl_withdrawals_settle_independently() {
    repeated_same_mint_spl_withdrawals_settle(ZolanaProgramTest::token_program_id());
}

#[test]
fn token_2022_withdrawals_settle_independently() {
    repeated_same_mint_spl_withdrawals_settle(ZolanaProgramTest::token_2022_program_id());
}

#[test]
fn three_distinct_assets_support_opposite_public_directions() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };
    let payer = env.rpc.payer.insecure_clone();
    let withdraw_mint = env.rpc.create_mint().expect("withdraw mint");
    let (note, withdraw_vault, _) = deposit_spl_note(&mut env, withdraw_mint, SPL_SPLIT_TOTAL);
    let withdraw_token = env
        .rpc
        .create_token_account(&withdraw_mint, &payer.pubkey())
        .expect("withdraw token account");

    let deposit_mint = env.rpc.create_mint().expect("deposit mint");
    let (_, deposit_vault) = env
        .rpc
        .create_spl_interface(&env.authority, &deposit_mint)
        .expect("deposit SPL interface");
    let deposit_token = env
        .rpc
        .create_token_account(&deposit_mint, &payer.pubkey())
        .expect("deposit token account");
    let spl_deposit_amount = 250u64;
    env.rpc
        .mint_to(&deposit_mint, &deposit_token, spl_deposit_amount)
        .expect("mint deposit tokens");
    let sol_deposit_amount = 10_000_000u64;

    let payer_owner = PublicKey::from_ed25519(&payer.pubkey().to_bytes());
    let outputs = vec![
        real_witness_output(
            payer_owner,
            note.nullifier_pk,
            SOL_MINT,
            sol_deposit_amount,
            [41u8; 31],
        ),
        real_witness_output(
            payer_owner,
            note.nullifier_pk,
            Address::new_from_array(deposit_mint.to_bytes()),
            spl_deposit_amount,
            [42u8; 31],
        ),
        dummy_outputs(env.rpc.payer.pubkey().to_bytes())
            .into_iter()
            .next()
            .expect("dummy output"),
    ];
    let interface_transfers = vec![
        InterfaceTransfer::SplWithdrawal {
            amount: SPL_SPLIT_TOTAL,
            spl_interface_bump: pda::spl_interface_with_bump(&withdraw_mint).1,
        },
        InterfaceTransfer::SolDeposit {
            amount: sol_deposit_amount,
        },
        InterfaceTransfer::SplDeposit {
            amount: spl_deposit_amount,
            spl_interface_bump: pda::spl_interface_with_bump(&deposit_mint).1,
        },
    ];
    let resolved_transfers = [
        ResolvedInterfaceTransfer::SplWithdrawal {
            amount: SPL_SPLIT_TOTAL,
            user_token_account: withdraw_token.to_bytes(),
            spl_interface: withdraw_vault.to_bytes(),
        },
        ResolvedInterfaceTransfer::SolDeposit {
            amount: sol_deposit_amount,
            recipient: payer.pubkey().to_bytes(),
        },
        ResolvedInterfaceTransfer::SplDeposit {
            amount: spl_deposit_amount,
            user_token_account: deposit_token.to_bytes(),
            spl_interface: deposit_vault.to_bytes(),
        },
    ];
    let withdraw_field = zolana_hasher::primitives::hash_bytes(&withdraw_mint.to_bytes())
        .expect("withdraw mint field");
    let deposit_field = zolana_hasher::primitives::hash_bytes(&deposit_mint.to_bytes())
        .expect("deposit mint field");
    let data = prove_spend(
        &env,
        note,
        interface_transfers,
        &resolved_transfers,
        [
            (withdraw_field, -(SPL_SPLIT_TOTAL as i64)),
            (SOL_ASSET_FIELD, sol_deposit_amount as i64),
            (deposit_field, spl_deposit_amount as i64),
        ],
        outputs,
    );
    let spl_withdrawal = |vault, user_token_account| {
        TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
            mint: withdraw_mint,
            spl_interface: vault,
            user_token_account,
            token_program: ZolanaProgramTest::token_program_id(),
        })
    };
    let spl_deposit = |vault, user_token_account| {
        TransactInterfaceTransferAccounts::SplDeposit(TransactSplDepositAccounts {
            mint: deposit_mint,
            spl_interface: vault,
            token_authority: payer.pubkey(),
            user_token_account,
            token_program: ZolanaProgramTest::token_program_id(),
        })
    };
    let sol_vault = pda::sol_interface();
    let sol_vault_before = env.rpc.svm.get_balance(&sol_vault).unwrap_or(0);
    let ix = Transact {
        payer: payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![
            spl_withdrawal(withdraw_vault, withdraw_token),
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                recipient: payer.pubkey(),
            }),
            spl_deposit(deposit_vault, deposit_token),
        ],
        data,
    }
    .instruction();
    let outcome = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect("three-asset mixed-direction transact");
    assert_eq!(
        env.rpc.token_balance(&withdraw_token),
        Some(SPL_SPLIT_TOTAL)
    );
    assert_eq!(env.rpc.token_balance(&deposit_token), Some(0));
    assert_eq!(
        env.rpc.token_balance(&deposit_vault),
        Some(spl_deposit_amount)
    );
    assert_eq!(
        env.rpc.svm.get_balance(&sol_vault).unwrap_or(0),
        sol_vault_before + sol_deposit_amount
    );
    let event = outcome.events.first().expect("transact event");
    assert_eq!(outcome.events.len(), 1);
    let event = general_event_from_indexed(event).expect("decode transact event");
    assert_eq!(
        event.spl_transfers,
        vec![
            SplTransfer {
                is_deposit: false,
                amount: SPL_SPLIT_TOTAL,
                asset: Some(withdraw_mint.to_bytes()),
            },
            SplTransfer {
                is_deposit: true,
                amount: sol_deposit_amount,
                asset: None,
            },
            SplTransfer {
                is_deposit: true,
                amount: spl_deposit_amount,
                asset: Some(deposit_mint.to_bytes()),
            },
        ]
    );
}
