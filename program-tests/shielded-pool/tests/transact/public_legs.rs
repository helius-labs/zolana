//! Validation coverage for public settlement legs. Invalid shapes fail before
//! proof verification and leave settlement balances unchanged.

#[path = "../common/setup.rs"]
mod common;

use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            CircuitId, InputUtxo, OwnerTag, PublicLeg, TransactIxData, TransactOutput,
            TransactProof,
        },
        Transact, TransactLegAccounts, TransactSolLeg, TransactSplLeg,
    },
    pda,
};
use zolana_program_test::ZolanaProgramTest;

fn fe(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn input(nullifier_hash: [u8; 32]) -> InputUtxo {
    InputUtxo {
        nullifier_hash,
        nullifier_tree_root_index: 0,
        utxo_tree_root_index: 0,
        tree_index: 0,
        eddsa_signer_index: 0,
    }
}

fn output(view_tag: [u8; 32]) -> TransactOutput {
    TransactOutput {
        utxo_hash: view_tag,
        owner_tag: OwnerTag::Inline(view_tag),
        data: None,
    }
}

fn ix_data(public_legs: Vec<PublicLeg>) -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed_eddsa(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa,
        p256_signing_pk_x: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: vec![input(fe(101)), input(fe(102))],
        public_legs,
        data_hash: None,
        zone_data_hash: None,
        outputs: vec![output([1u8; 32]), output([2u8; 32]), output([3u8; 32])],
        messages: Vec::new(),
    }
}

fn send_raw(
    rpc: &mut ZolanaProgramTest,
    ix: solana_instruction::Instruction,
    payer: &Keypair,
) -> Result<(), String> {
    let blockhash = rpc.svm.latest_blockhash();
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, blockhash);
    rpc.svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

fn assert_rejected_without_sol_movement(public_legs: Vec<PublicLeg>, expected_error: u32) {
    let Some(mut rpc) = common::program_test() else {
        return;
    };
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    let payer = rpc.payer.insecure_clone();
    let legs = public_legs
        .iter()
        .map(|_| {
            TransactLegAccounts::Sol(TransactSolLeg {
                recipient: payer.pubkey(),
            })
        })
        .collect();
    let ix = Transact {
        payer: payer.pubkey(),
        tree: tree.pubkey(),
        legs,
        data: ix_data(public_legs),
    }
    .instruction();

    let sol_vault = pda::sol_interface();
    let vault_before = rpc.svm.get_balance(&sol_vault).unwrap_or(0);
    let err = send_raw(&mut rpc, ix, &payer).expect_err("invalid public legs must fail");
    assert!(
        err.contains(&format!("Custom({expected_error})")),
        "expected custom error {expected_error}, got: {err}"
    );
    assert_eq!(rpc.svm.get_balance(&sol_vault).unwrap_or(0), vault_before);
}

#[test]
fn six_same_asset_public_legs_reach_proof_verification() {
    let Some(mut rpc) = common::program_test() else {
        return;
    };
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    let payer = rpc.payer.insecure_clone();
    let public_legs = vec![
        PublicLeg::Sol {
            is_deposit: true,
            amount: 1,
        };
        6
    ];
    let ix = Transact {
        payer: payer.pubkey(),
        tree: tree.pubkey(),
        legs: vec![
            TransactLegAccounts::Sol(TransactSolLeg {
                recipient: payer.pubkey(),
            });
            public_legs.len()
        ],
        data: ix_data(public_legs),
    }
    .instruction();
    let vault = pda::sol_interface();
    let before = rpc.svm.get_balance(&vault).unwrap_or(0);
    let err = send_raw(&mut rpc, ix, &payer).expect_err("dummy proof must fail");
    assert!(
        err.contains("Custom(7008)"),
        "six same-asset legs must pass validation and reach proof verification: {err}"
    );
    assert_eq!(rpc.svm.get_balance(&vault).unwrap_or(0), before);
}

#[test]
fn zero_public_leg_is_rejected() {
    assert_rejected_without_sol_movement(
        vec![PublicLeg::Sol {
            is_deposit: true,
            amount: 0,
        }],
        7033,
    );
}

#[test]
fn same_asset_aggregate_overflow_is_rejected() {
    assert_rejected_without_sol_movement(
        vec![
            PublicLeg::Sol {
                is_deposit: true,
                amount: u64::MAX,
            },
            PublicLeg::Sol {
                is_deposit: true,
                amount: 1,
            },
        ],
        7035,
    );
}

#[test]
fn full_u64_spl_cancellation_and_net_withdrawal_reach_proof_verification() {
    let Some(mut rpc) = common::program_test() else {
        return;
    };
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    let payer = rpc.payer.insecure_clone();
    rpc.ensure_asset_counter(&authority).expect("asset counter");
    let mint = rpc.create_mint().expect("create mint");
    let (_, vault) = rpc
        .create_spl_interface(&authority, &mint)
        .expect("create SPL interface");
    let user_token_account = rpc
        .create_token_account(&mint, &payer.pubkey())
        .expect("create payer token account");
    let spl_leg = || {
        TransactLegAccounts::Spl(TransactSplLeg {
            vault,
            recipient: payer.pubkey(),
            user_token_account,
            token_program: ZolanaProgramTest::token_program_id(),
        })
    };
    let vault_bump = pda::spl_asset_vault_with_bump(&mint).1;
    let ix = Transact {
        payer: payer.pubkey(),
        tree: tree.pubkey(),
        legs: vec![spl_leg(), spl_leg(), spl_leg()],
        data: ix_data(vec![
            PublicLeg::Spl {
                is_deposit: true,
                amount: u64::MAX,
                vault_bump,
            },
            PublicLeg::Spl {
                is_deposit: false,
                amount: u64::MAX,
                vault_bump,
            },
            PublicLeg::Spl {
                is_deposit: false,
                amount: u64::MAX,
                vault_bump,
            },
        ]),
    }
    .instruction();

    let before = rpc.token_balance(&vault).expect("vault balance");
    let err = send_raw(&mut rpc, ix, &payer).expect_err("dummy proof must fail");
    assert!(
        err.contains("Custom(7008)"),
        "full-u64 cancellation and net withdrawal must reach proof verification: {err}"
    );
    assert_eq!(rpc.token_balance(&vault), Some(before));
}

#[test]
fn spl_settlement_rejects_noncanonical_vault_bump() {
    let Some(mut rpc) = common::program_test() else {
        return;
    };
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    let payer = rpc.payer.insecure_clone();
    rpc.ensure_asset_counter(&authority).expect("asset counter");
    let mint = rpc.create_mint().expect("create mint");
    let (_, vault) = rpc
        .create_spl_interface(&authority, &mint)
        .expect("create SPL interface");
    let user_token_account = rpc
        .create_token_account(&mint, &payer.pubkey())
        .expect("create payer token account");
    rpc.mint_to(&mint, &user_token_account, 1)
        .expect("mint deposit token");

    let canonical_bump = pda::spl_asset_vault_with_bump(&mint).1;
    let ix = Transact {
        payer: payer.pubkey(),
        tree: tree.pubkey(),
        legs: vec![TransactLegAccounts::Spl(TransactSplLeg {
            vault,
            recipient: payer.pubkey(),
            user_token_account,
            token_program: ZolanaProgramTest::token_program_id(),
        })],
        data: ix_data(vec![PublicLeg::Spl {
            is_deposit: true,
            amount: 1,
            vault_bump: canonical_bump.wrapping_add(1),
        }]),
    }
    .instruction();

    let vault_before = rpc.token_balance(&vault).expect("vault balance");
    let user_before = rpc
        .token_balance(&user_token_account)
        .expect("user token balance");
    let err = send_raw(&mut rpc, ix, &payer).expect_err("wrong vault bump must fail");
    assert!(
        err.contains("Custom(7009)"),
        "expected InvalidSettlementAccounts (7009), got: {err}"
    );
    assert_eq!(rpc.token_balance(&vault), Some(vault_before));
    assert_eq!(rpc.token_balance(&user_token_account), Some(user_before));
}

#[test]
fn four_distinct_public_assets_are_rejected() {
    let Some(mut rpc) = common::program_test() else {
        return;
    };
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    let payer = rpc.payer.insecure_clone();
    rpc.ensure_asset_counter(&authority).expect("asset counter");

    let mut legs = Vec::new();
    let mut vaults = Vec::new();
    let mut public_legs = Vec::new();
    for _ in 0..4 {
        let mint = rpc.create_mint().expect("create mint");
        let (_, vault) = rpc
            .create_spl_interface(&authority, &mint)
            .expect("create SPL interface");
        let user_token_account = rpc
            .create_token_account(&mint, &payer.pubkey())
            .expect("create payer token account");
        rpc.mint_to(&mint, &user_token_account, 1)
            .expect("mint deposit token");
        legs.push(TransactLegAccounts::Spl(TransactSplLeg {
            vault,
            recipient: payer.pubkey(),
            user_token_account,
            token_program: ZolanaProgramTest::token_program_id(),
        }));
        vaults.push(vault);
        public_legs.push(PublicLeg::Spl {
            is_deposit: true,
            amount: 1,
            vault_bump: pda::spl_asset_vault_with_bump(&mint).1,
        });
    }
    let vault_balances: Vec<u64> = vaults
        .iter()
        .map(|vault| rpc.token_balance(vault).unwrap_or(0))
        .collect();
    let ix = Transact {
        payer: payer.pubkey(),
        tree: tree.pubkey(),
        legs,
        data: ix_data(public_legs),
    }
    .instruction();

    let err = send_raw(&mut rpc, ix, &payer).expect_err("four public assets must fail");
    assert!(
        err.contains("Custom(7034)"),
        "expected TooManyPublicAssets (7034), got: {err}"
    );
    for (vault, before) in vaults.iter().zip(vault_balances) {
        assert_eq!(rpc.token_balance(vault).unwrap_or(0), before);
    }
}
