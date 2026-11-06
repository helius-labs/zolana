use serde_json::{json, Value};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use spr_instruction::instruction::{
    RingTransact, Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    TransactSplDepositAccounts, TransactSplWithdrawalAccounts,
};
use spr_interface::{
    instruction::{
        CircuitId, InputUtxo, InterfaceTransfer, TransactIxData, TransactProof, TreeContext,
    },
    pda,
};

const SETTLEMENT_VECTORS_JSON: &str =
    include_str!("../../../test-vectors/transact_settlements.json");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn field(seed: u8) -> [u8; 32] {
    let mut bytes = [seed; 32];
    bytes[0] = 0;
    bytes
}

fn address(seed: u8) -> Pubkey {
    Pubkey::new_from_array([seed; 32])
}

fn account_metas(accounts: &[AccountMeta]) -> Value {
    Value::Array(
        accounts
            .iter()
            .map(|meta| {
                json!({
                    "address": meta.pubkey.to_string(),
                    "signer": meta.is_signer,
                    "writable": meta.is_writable,
                })
            })
            .collect(),
    )
}

fn instruction_vector(instruction: &Instruction) -> Value {
    json!({
        "programAddress": instruction.program_id.to_string(),
        "data": hex(&instruction.data),
        "accounts": account_metas(&instruction.accounts),
    })
}

/// Every leg kind once, in an order that interleaves deposits and
/// withdrawals, so a builder that groups by kind or by direction fails.
fn legs() -> (
    Vec<InterfaceTransfer>,
    Vec<TransactInterfaceTransferAccounts>,
) {
    let deposit_mint = address(0x31);
    let withdrawal_mint = address(0x32);
    let (deposit_interface, deposit_bump) = pda::spl_interface_with_bump(&deposit_mint);
    let (withdrawal_interface, withdrawal_bump) = pda::spl_interface_with_bump(&withdrawal_mint);
    (
        vec![
            InterfaceTransfer::SplWithdrawal {
                amount: 4_000,
                spl_interface_bump: withdrawal_bump,
            },
            InterfaceTransfer::SolDeposit { amount: 1_000 },
            InterfaceTransfer::SplDeposit {
                amount: 2_000,
                spl_interface_bump: deposit_bump,
            },
            InterfaceTransfer::SolWithdrawal { amount: 3_000 },
        ],
        vec![
            TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
                mint: withdrawal_mint,
                spl_interface: withdrawal_interface,
                user_token_account: address(0x41),
                token_program: pda::spl_token_program_id(),
            }),
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                recipient: address(0x42),
            }),
            TransactInterfaceTransferAccounts::SplDeposit(TransactSplDepositAccounts {
                mint: deposit_mint,
                spl_interface: deposit_interface,
                token_authority: address(0x43),
                user_token_account: address(0x44),
                token_program: pda::spl_token_2022_program_id(),
            }),
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                recipient: address(0x45),
            }),
        ],
    )
}

fn transfer_json(transfer: &InterfaceTransfer) -> Value {
    match transfer {
        InterfaceTransfer::SolDeposit { amount } => {
            json!({ "kind": "solDeposit", "amount": amount.to_string() })
        }
        InterfaceTransfer::SolWithdrawal { amount } => {
            json!({ "kind": "solWithdrawal", "amount": amount.to_string() })
        }
        InterfaceTransfer::SplDeposit {
            amount,
            spl_interface_bump,
        } => json!({
            "kind": "splDeposit",
            "amount": amount.to_string(),
            "splInterfaceBump": spl_interface_bump,
        }),
        InterfaceTransfer::SplWithdrawal {
            amount,
            spl_interface_bump,
        } => json!({
            "kind": "splWithdrawal",
            "amount": amount.to_string(),
            "splInterfaceBump": spl_interface_bump,
        }),
    }
}

/// The TypeScript SDK names the SOL group by its leg's direction.
fn settlement_json(
    transfer: &InterfaceTransfer,
    group: &TransactInterfaceTransferAccounts,
) -> Value {
    match (transfer, group) {
        (InterfaceTransfer::SolDeposit { .. }, TransactInterfaceTransferAccounts::Sol(sol)) => {
            json!({ "kind": "solDeposit", "depositor": sol.recipient.to_string() })
        }
        (InterfaceTransfer::SolWithdrawal { .. }, TransactInterfaceTransferAccounts::Sol(sol)) => {
            json!({ "kind": "solWithdrawal", "recipient": sol.recipient.to_string() })
        }
        (_, TransactInterfaceTransferAccounts::SplDeposit(spl)) => json!({
            "kind": "splDeposit",
            "mint": spl.mint.to_string(),
            "splTokenInterface": spl.spl_interface.to_string(),
            "tokenAuthority": spl.token_authority.to_string(),
            "sourceTokenAccount": spl.user_token_account.to_string(),
            "tokenProgram": spl.token_program.to_string(),
        }),
        (_, TransactInterfaceTransferAccounts::SplWithdrawal(spl)) => json!({
            "kind": "splWithdrawal",
            "mint": spl.mint.to_string(),
            "splTokenInterface": spl.spl_interface.to_string(),
            "recipientTokenAccount": spl.user_token_account.to_string(),
            "tokenProgram": spl.token_program.to_string(),
        }),
        _ => panic!("a SOL group settles a SOL leg"),
    }
}

fn transact_data(interface_transfers: Vec<InterfaceTransfer>) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: 77,
        tx_viewing_pk: [3; 33],
        salt: [4; 16],
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: Vec::new(),
        private_tx_hash: field(5),
        circuit: CircuitId::ConfidentialSigner(2, 2, 3),
        proof: TransactProof {
            a: [6; 32],
            b: [7; 128],
            c: [8; 32],
        },
        inputs: (0..2)
            .map(|index| InputUtxo {
                nullifier_hash: field(0x10 + index),
                tree_index: 0,
            })
            .collect(),
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 9,
            nullifier_tree_root_index: 10,
        }],
    }
}

fn compute_settlement_vectors() -> Value {
    let payer = address(0x11);
    let input_tree = address(0x12);
    let output_tree = address(0x13);
    let owner_signer = address(0x14);
    let signer_pda = address(0x15);
    let ring_program_id = address(0x16);
    let (transfers, groups) = legs();
    let transact = Transact {
        payer,
        input_trees: vec![input_tree],
        output_tree,
        owner_signers: vec![owner_signer],
        interface_transfer_accounts: groups.clone(),
        data: transact_data(transfers.clone()),
    };
    let ring_transact = RingTransact {
        payer,
        input_trees: vec![input_tree],
        output_tree,
        ring_program_id,
        owner_signers: vec![owner_signer],
        interface_transfer_accounts: groups.clone(),
        data: transact_data(transfers.clone()),
    };
    json!({
        "description": "Account layouts of a transact with one settlement group per interface transfer, which the TypeScript SDK must reproduce: the instruction, the CPI account list with a signing PDA, and the ring transact sent to the ring program. Regenerate with `cargo test -p spr-instruction --test settlement_vectors print_settlement_vectors -- --ignored --nocapture`.",
        "payer": payer.to_string(),
        "inputTree": input_tree.to_string(),
        "outputTree": output_tree.to_string(),
        "ownerSigner": owner_signer.to_string(),
        "signerPda": signer_pda.to_string(),
        "ringProgramId": ring_program_id.to_string(),
        "ringAuth": pda::ring_auth(&ring_program_id).0.to_string(),
        "interfaceTransfers": transfers.iter().map(transfer_json).collect::<Vec<_>>(),
        "settlements": transfers
            .iter()
            .zip(&groups)
            .map(|(transfer, group)| settlement_json(transfer, group))
            .collect::<Vec<_>>(),
        "transact": instruction_vector(&transact.instruction()),
        "transactCpiAccounts": account_metas(&transact.cpi_accounts(&[signer_pda])),
        "ringTransact": instruction_vector(&ring_transact.instruction()),
    })
}

#[test]
fn settlement_layouts_match_the_shared_vectors() {
    let committed: Value =
        serde_json::from_str(SETTLEMENT_VECTORS_JSON).expect("shared settlement vectors");
    assert_eq!(committed, compute_settlement_vectors());
}

#[test]
#[ignore = "regenerates test-vectors/transact_settlements.json; run with --nocapture and commit the output"]
fn print_settlement_vectors() {
    println!(
        "{}",
        serde_json::to_string_pretty(&compute_settlement_vectors()).expect("json")
    );
}
