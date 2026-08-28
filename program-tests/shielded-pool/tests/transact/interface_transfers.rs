//! Validation coverage for interface transfers. Invalid shapes fail before
//! proof verification and leave settlement balances unchanged.

use shielded_pool_tests::support::fixtures::{register_mint, Pool};

use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{CircuitId, InterfaceTransfer, TransactIxData, TransactProof},
        Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
        TransactSplDepositAccounts, TransactSplWithdrawalAccounts,
    },
    pda, N_PUBLIC_SLOTS,
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::transact::{eddsa_input_utxo, fe, inline_output};

/// Two-input/three-output transact data with a zeroed proof carrying the
/// given interface transfers: the validation failures under test fire before
/// proof verification, and the valid shapes stop at the dummy-proof check.
fn ix_data(interface_transfers: Vec<InterfaceTransfer>) -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa(2, 3, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: vec![eddsa_input_utxo(fe(101), 0), eddsa_input_utxo(fe(102), 0)],
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![
            inline_output([1u8; 32], [1u8; 32]),
            inline_output([2u8; 32], [2u8; 32]),
            inline_output([3u8; 32], [3u8; 32]),
        ],
        messages: Vec::new(),
    }
}

/// Send the transact with the default payer and assert the exact typed
/// rejection plus a full rollback (a failed transaction only charges the
/// payer's fee).
#[track_caller]
fn expect_rejection(rpc: &mut ZolanaProgramTest, ix: Instruction, expected: Rejection) {
    let payer = rpc.payer.pubkey();
    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("interface-transfer transact must be rejected");
    expected.assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("rejected transact trace")
        .assert_rolled_back_except(&[payer]);
}

/// An invalid SOL-leg shape must be rejected during validation, before proof
/// verification, without moving lamports out of the SOL interface vault.
#[track_caller]
fn assert_rejected_without_sol_movement(
    interface_transfers: Vec<InterfaceTransfer>,
    expected: ShieldedPoolError,
) {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();
    let interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts> = interface_transfers
        .iter()
        .map(|_| {
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient: payer })
        })
        .collect();
    // The `Transact` builder's validating serializer rejects invalid legs
    // client-side, so these on-chain validation tests serialize directly
    // (wincode carries no validation) and lay out the accounts by hand.
    let data = ix_data(interface_transfers);
    let mut instruction_data = vec![zolana_interface::instruction::tag::TRANSACT];
    instruction_data.extend_from_slice(
        &wincode::serialize(&data).expect("wincode serialization is infallible"),
    );
    let mut accounts = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(pool.tree.pubkey(), false),
        AccountMeta::new(pool.tree.pubkey(), false),
        AccountMeta::new_readonly(zolana_interface::PROGRAM_ID_PUBKEY, false),
        AccountMeta::new_readonly(Pubkey::default(), false),
    ];
    accounts.extend(data.inputs.iter().map(|input| {
        AccountMeta::new(
            pda::nullifier_marker(&pool.tree.pubkey(), &input.nullifier_hash).0,
            false,
        )
    }));
    for _ in &interface_transfer_accounts {
        accounts.push(AccountMeta::new(pda::sol_interface(), false));
        accounts.push(AccountMeta::new(payer, true));
    }
    let ix = Instruction {
        program_id: zolana_interface::PROGRAM_ID_PUBKEY,
        accounts,
        data: instruction_data,
    };

    let sol_vault = pda::sol_interface();
    let vault_before = pool.rpc.svm.get_balance(&sol_vault).unwrap_or(0);
    expect_rejection(&mut pool.rpc, ix, Rejection::pool(expected));
    assert_eq!(
        pool.rpc.svm.get_balance(&sol_vault).unwrap_or(0),
        vault_before
    );
}

#[test]
fn six_same_asset_interface_transfers_reach_proof_verification() {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();
    let interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 1 }; 6];
    let ix = Transact {
        payer,
        input_tree: pool.tree.pubkey(),
        output_tree: pool.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![
            TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient: payer }
            );
            interface_transfers.len()
        ],
        data: ix_data(interface_transfers),
    }
    .instruction();
    let vault = pda::sol_interface();
    let before = pool.rpc.svm.get_balance(&vault).unwrap_or(0);
    expect_rejection(
        &mut pool.rpc,
        ix,
        Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed),
    );
    assert_eq!(pool.rpc.svm.get_balance(&vault).unwrap_or(0), before);
}

#[test]
fn zero_interface_transfer_is_rejected() {
    assert_rejected_without_sol_movement(
        vec![InterfaceTransfer::SolDeposit { amount: 0 }],
        ShieldedPoolError::ZeroInterfaceTransferAmount,
    );
}

#[test]
fn same_asset_aggregate_overflow_is_rejected() {
    assert_rejected_without_sol_movement(
        vec![
            InterfaceTransfer::SolDeposit { amount: u64::MAX },
            InterfaceTransfer::SolDeposit { amount: 1 },
        ],
        ShieldedPoolError::PublicAssetAmountOverflow,
    );
}

#[test]
fn full_u64_spl_cancellation_and_net_withdrawal_reach_proof_verification() {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();
    let (mint, _, vault) = register_mint(&mut pool);
    let user_token_account = pool
        .rpc
        .create_token_account(&mint, &payer)
        .expect("create payer token account");
    let spl_deposit = || {
        TransactInterfaceTransferAccounts::SplDeposit(TransactSplDepositAccounts {
            mint,
            spl_interface: vault,
            token_authority: payer,
            user_token_account,
            token_program: ZolanaProgramTest::token_program_id(),
        })
    };
    let spl_withdrawal = || {
        TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
            mint,
            spl_interface: vault,
            user_token_account,
            token_program: ZolanaProgramTest::token_program_id(),
        })
    };
    let spl_interface_bump = pda::spl_interface_with_bump(&mint).1;
    let ix = Transact {
        payer,
        input_tree: pool.tree.pubkey(),
        output_tree: pool.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![spl_deposit(), spl_withdrawal(), spl_withdrawal()],
        data: ix_data(vec![
            InterfaceTransfer::SplDeposit {
                amount: u64::MAX,
                spl_interface_bump,
            },
            InterfaceTransfer::SplWithdrawal {
                amount: u64::MAX,
                spl_interface_bump,
            },
            InterfaceTransfer::SplWithdrawal {
                amount: u64::MAX,
                spl_interface_bump,
            },
        ]),
    }
    .instruction();

    let before = pool.rpc.token_balance(&vault).expect("vault balance");
    expect_rejection(
        &mut pool.rpc,
        ix,
        Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed),
    );
    assert_eq!(pool.rpc.token_balance(&vault), Some(before));
}

#[test]
fn token_2022_withdrawal_accounts_reach_proof_verification() {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let token_program = ZolanaProgramTest::token_2022_program_id();
    let mint = pool
        .rpc
        .create_mint_with_program(token_program)
        .expect("create Token-2022 mint");
    let (_, vault) = pool
        .rpc
        .create_spl_interface_with_program(&pool.authority, &mint, token_program)
        .expect("create Token-2022 interface");
    let recipient = pool
        .rpc
        .create_token_account_with_program(&mint, &payer, token_program)
        .expect("create Token-2022 recipient");
    pool.rpc
        .mint_to_with_program(&mint, &vault, 1, token_program)
        .expect("fund Token-2022 vault");

    let ix = Transact {
        payer,
        input_tree: pool.tree.pubkey(),
        output_tree: pool.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplWithdrawal(
            TransactSplWithdrawalAccounts {
                mint,
                spl_interface: vault,
                user_token_account: recipient,
                token_program,
            },
        )],
        data: ix_data(vec![InterfaceTransfer::SplWithdrawal {
            amount: 1,
            spl_interface_bump: pda::spl_interface_with_bump(&mint).1,
        }]),
    }
    .instruction();

    expect_rejection(
        &mut pool.rpc,
        ix,
        Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed),
    );
    assert_eq!(pool.rpc.token_balance(&vault), Some(1));
    assert_eq!(pool.rpc.token_balance(&recipient), Some(0));
}

#[test]
fn spl_settlement_rejects_noncanonical_vault_bump() {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();
    let (mint, _, vault) = register_mint(&mut pool);
    let user_token_account = pool
        .rpc
        .create_token_account(&mint, &payer)
        .expect("create payer token account");
    pool.rpc
        .mint_to(&mint, &user_token_account, 1)
        .expect("mint deposit token");

    let canonical_bump = pda::spl_interface_with_bump(&mint).1;
    let ix = Transact {
        payer,
        input_tree: pool.tree.pubkey(),
        output_tree: pool.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplDeposit(
            TransactSplDepositAccounts {
                mint,
                spl_interface: vault,
                token_authority: payer,
                user_token_account,
                token_program: ZolanaProgramTest::token_program_id(),
            },
        )],
        data: ix_data(vec![InterfaceTransfer::SplDeposit {
            amount: 1,
            spl_interface_bump: canonical_bump.wrapping_add(1),
        }]),
    }
    .instruction();

    let vault_before = pool.rpc.token_balance(&vault).expect("vault balance");
    let user_before = pool
        .rpc
        .token_balance(&user_token_account)
        .expect("user token balance");
    expect_rejection(
        &mut pool.rpc,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts),
    );
    assert_eq!(pool.rpc.token_balance(&vault), Some(vault_before));
    assert_eq!(
        pool.rpc.token_balance(&user_token_account),
        Some(user_before)
    );
}

#[test]
fn spl_deposit_requires_depositor_signature() {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();
    let (mint, _, vault) = register_mint(&mut pool);
    let depositor = Keypair::new();
    let user_token_account = pool
        .rpc
        .create_token_account(&mint, &depositor.pubkey())
        .expect("create depositor token account");
    pool.rpc
        .mint_to(&mint, &user_token_account, 1)
        .expect("mint deposit token");

    let data = ix_data(vec![InterfaceTransfer::SplDeposit {
        amount: 1,
        spl_interface_bump: pda::spl_interface_with_bump(&mint).1,
    }]);
    let token_authority_index = 7 + data.inputs.len();
    let mut ix = Transact {
        payer,
        input_tree: pool.tree.pubkey(),
        output_tree: pool.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplDeposit(
            TransactSplDepositAccounts {
                mint,
                spl_interface: vault,
                token_authority: depositor.pubkey(),
                user_token_account,
                token_program: ZolanaProgramTest::token_program_id(),
            },
        )],
        data,
    }
    .instruction();
    // Accounts: [payer, trees, program, system, one marker per input, mint,
    // spl_interface, token_authority, user_token, token_program].
    ix.accounts
        .get_mut(token_authority_index)
        .expect("token_authority meta")
        .is_signer = false;

    expect_rejection(
        &mut pool.rpc,
        ix,
        Rejection::pool(ShieldedPoolError::SplTokenAuthorityMustSign),
    );
}

/// Grafting an extra account into the settlement group before the token
/// program lands the stranger in the `token_program` slot, so validation
/// rejects it as invalid settlement accounts before any CPI runs. The grafted
/// account must be a fresh pubkey: the runtime deduplicates metas by address,
/// so a repeated payer would collapse away the shift. (On the transact path an
/// unsupported token program maps to 7009; `UnsupportedSplTokenProgram` = 7041
/// is the create_spl_interface surface.)
#[test]
fn spl_withdrawal_rejects_a_shifted_token_program_account() {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();
    let (mint, _, vault) = register_mint(&mut pool);
    let user_token_account = pool
        .rpc
        .create_token_account(&mint, &payer)
        .expect("create recipient token account");
    pool.rpc.mint_to(&mint, &vault, 1).expect("fund vault");

    let mut ix = Transact {
        payer,
        input_tree: pool.tree.pubkey(),
        output_tree: pool.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplWithdrawal(
            TransactSplWithdrawalAccounts {
                mint,
                spl_interface: vault,
                user_token_account,
                token_program: ZolanaProgramTest::token_program_id(),
            },
        )],
        data: ix_data(vec![InterfaceTransfer::SplWithdrawal {
            amount: 1,
            spl_interface_bump: pda::spl_interface_with_bump(&mint).1,
        }]),
    }
    .instruction();
    // Accounts: [payer, trees, program, system, cpi_authority, mint,
    // spl_interface, user_token, token_program(9)].
    ix.accounts
        .insert(9, AccountMeta::new_readonly(Pubkey::new_unique(), false));

    expect_rejection(
        &mut pool.rpc,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts),
    );
}

#[test]
fn four_distinct_public_assets_are_rejected() {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();

    let mut interface_transfer_accounts = Vec::new();
    let mut vaults = Vec::new();
    let mut interface_transfers = Vec::new();
    for _ in 0..4 {
        let (mint, _, vault) = register_mint(&mut pool);
        let user_token_account = pool
            .rpc
            .create_token_account(&mint, &payer)
            .expect("create payer token account");
        pool.rpc
            .mint_to(&mint, &user_token_account, 1)
            .expect("mint deposit token");
        interface_transfer_accounts.push(TransactInterfaceTransferAccounts::SplDeposit(
            TransactSplDepositAccounts {
                mint,
                spl_interface: vault,
                token_authority: payer,
                user_token_account,
                token_program: ZolanaProgramTest::token_program_id(),
            },
        ));
        vaults.push(vault);
        interface_transfers.push(InterfaceTransfer::SplDeposit {
            amount: 1,
            spl_interface_bump: pda::spl_interface_with_bump(&mint).1,
        });
    }
    let vault_balances: Vec<u64> = vaults
        .iter()
        .map(|vault| pool.rpc.token_balance(vault).unwrap_or(0))
        .collect();
    let ix = Transact {
        payer,
        input_tree: pool.tree.pubkey(),
        output_tree: pool.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts,
        data: ix_data(interface_transfers),
    }
    .instruction();

    expect_rejection(
        &mut pool.rpc,
        ix,
        Rejection::pool(ShieldedPoolError::TooManyPublicAssets),
    );
    for (vault, before) in vaults.iter().zip(vault_balances) {
        assert_eq!(pool.rpc.token_balance(vault).unwrap_or(0), before);
    }
}
