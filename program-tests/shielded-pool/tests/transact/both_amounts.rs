//! C-01 regression: a both-amounts `transact` used to mint an unbacked note,
//! because the parser settles one asset (SPL when `public_spl_amount` is set)
//! while the proven SOL leg never moved. The fix rejects both-present up front.
//!
//! Asserts the program returns `BothPublicAmountsSet` (7023) and moves no tokens.
//! The reject precedes proof verification, so no real proof is needed. Skips when
//! the program `.so` is missing.

#[path = "../common/setup.rs"]
mod common;

use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{InputUtxo, OutputCiphertext, TransactIxData, TransactProof},
        Transact, TransactSplWithdrawal, TransactWithdrawal,
    },
    pda,
};
use zolana_program_test::ZolanaProgramTest;

/// Error code for `ShieldedPoolError::BothPublicAmountsSet`.
const BOTH_PUBLIC_AMOUNTS_SET: u32 = 7023;

/// A field element holding `value` in its low 8 bytes (big-endian).
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

fn ciphertext(view_tag: [u8; 32]) -> OutputCiphertext {
    OutputCiphertext {
        view_tag,
        data: Vec::new(),
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

#[test]
fn both_public_amounts_are_rejected() {
    let Some(mut rpc) = common::program_test() else {
        return;
    };
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");

    let attacker = rpc.payer.insecure_clone();

    // Valid SPL accounts, so the tx reaches the guard, not an earlier account error.
    let mint = rpc.create_mint().expect("create mint");
    rpc.ensure_asset_counter(&authority).expect("asset counter");
    let (_registry, vault) = rpc
        .create_spl_interface(&authority, &mint)
        .expect("create spl interface");
    let attacker_ata = rpc
        .create_token_account(&mint, &attacker.pubkey())
        .expect("attacker ata");
    rpc.mint_to(&mint, &attacker_ata, 1_000).expect("mint dust");

    // Both amounts set: +1 SOL and +1000 SPL.
    let ix_data = TransactIxData {
        proof: TransactProof::zeroed_eddsa(),
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash: [0u8; 32],
        p256_signing_pk_field: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: vec![input(fe(101)), input(fe(102))],
        public_sol_amount: Some(1_000_000_000),
        public_spl_amount: Some(1_000),
        data_hash: None,
        zone_data_hash: None,
        output_utxo_hashes: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        output_ciphertexts: vec![
            ciphertext([1u8; 32]),
            ciphertext([2u8; 32]),
            ciphertext([3u8; 32]),
        ],
    };

    let ix = Transact {
        payer: attacker.pubkey(),
        tree: tree.pubkey(),
        withdrawal: Some(TransactWithdrawal::Spl(TransactSplWithdrawal {
            cpi_authority: None,
            spl_token_interface: vault,
            recipient: attacker.pubkey(),
            user_token_account: attacker_ata,
            token_program: ZolanaProgramTest::token_program_id(),
        })),
        data: ix_data,
    }
    .instruction();

    let ata_before = rpc.token_balance(&attacker_ata).unwrap_or(0);
    let vault_before = rpc.token_balance(&vault).unwrap_or(0);
    let sol_vault_before = rpc.svm.get_balance(&pda::sol_interface()).unwrap_or(0);

    let err =
        send_raw(&mut rpc, ix, &attacker).expect_err("both-amounts transact must be rejected");
    assert!(
        err.contains(&format!("Custom({BOTH_PUBLIC_AMOUNTS_SET})")),
        "expected BothPublicAmountsSet ({BOTH_PUBLIC_AMOUNTS_SET}), got: {err}"
    );

    // The guard fires before settlement, so nothing moved.
    assert_eq!(
        rpc.token_balance(&attacker_ata).unwrap_or(0),
        ata_before,
        "no SPL debited"
    );
    assert_eq!(
        rpc.token_balance(&vault).unwrap_or(0),
        vault_before,
        "no SPL credited"
    );
    assert_eq!(
        rpc.svm.get_balance(&pda::sol_interface()).unwrap_or(0),
        sol_vault_before,
        "no SOL moved"
    );
}
