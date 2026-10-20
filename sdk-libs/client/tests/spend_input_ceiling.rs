use solana_pubkey::Pubkey;
use zolana_client::{transaction_size, ComputeBudgetConfig, TransactionSize};
use zolana_interface::{
    instruction::{
        CircuitId, InputUtxo, InterfaceTransfer, OwnerTag, TransactIxData, TransactOutput,
        TransactProof, TreeContext,
    },
    MAX_INPUT_TREES, N_PUBLIC_SLOTS,
};
use zolana_keypair::ViewingKey;
use zolana_program::instruction::{
    Transact, TransactInterfaceTransferAccounts, TransactSplWithdrawalAccounts,
};
use zolana_transaction::{
    instructions::transact::{canonical_shape, MAX_SPEND_INPUTS},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    Data, SOL_ASSET_ID,
};

const OUTPUTS: usize = 2;

fn output_ciphertext_len() -> usize {
    let key = ViewingKey::new();
    Confidential::encode_plaintext(
        &ConfidentialOutputPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: u64::MAX,
            blinding: [0u8; 32],
            ring_program_id: None,
            data: Data::default(),
        },
        [0u8; 32],
        &ConfidentialEncode {
            recipient_pubkey: key.pubkey(),
            tx: key,
            salt: [0u8; 16],
            slot_index: 0,
        },
    )
    .expect("encode a confidential output")
    .data
    .len()
}

/// The largest wallet spend of `published_inputs` slots: every slot publishes
/// a nullifier (random padding), both outputs carry a ciphertext under an
/// inline tag, the inputs span every allowed tree, an owner other than the
/// payer signs, and an SPL withdrawal settles.
fn widest_wallet_spend(published_inputs: usize) -> TransactionSize {
    let payer = Pubkey::new_unique();
    let input_trees: Vec<Pubkey> = (0..MAX_INPUT_TREES).map(|_| Pubkey::new_unique()).collect();
    let tree_count = u8::try_from(MAX_INPUT_TREES).expect("tree count fits u8");
    let inputs = (0..published_inputs)
        .map(|index| {
            let seed = (index as u64 + 1).to_le_bytes();
            let nullifier_hash = core::array::from_fn(|byte| seed.get(byte).copied().unwrap_or(0));
            InputUtxo {
                nullifier_hash,
                tree_index: u8::try_from(index).expect("index fits u8") % tree_count,
            }
        })
        .collect();
    let ciphertext_len = output_ciphertext_len();
    let outputs = (0..OUTPUTS)
        .map(|_| TransactOutput {
            utxo_hash: [1u8; 32],
            owner_tag: OwnerTag::Inline([2u8; 32]),
            data: Some(vec![0u8; ciphertext_len]),
        })
        .collect();
    let transact = Transact {
        payer,
        input_trees: input_trees.clone(),
        output_tree: input_trees.first().copied().expect("one input tree"),
        owner_signers: vec![Pubkey::new_unique()],
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplWithdrawal(
            TransactSplWithdrawalAccounts {
                mint: Pubkey::new_unique(),
                spl_interface: Pubkey::new_unique(),
                user_token_account: Pubkey::new_unique(),
                token_program: Pubkey::new_unique(),
            },
        )],
        data: TransactIxData {
            expiry_unix_ts: u64::MAX,
            tx_viewing_pk: [3u8; 33],
            salt: [4u8; 16],
            interface_transfers: vec![InterfaceTransfer::SplWithdrawal {
                amount: u64::MAX,
                spl_interface_bump: 255,
            }],
            data_hash: None,
            ring_data_hash: None,
            outputs,
            messages: Vec::new(),
            private_tx_hash: [5u8; 32],
            circuit: CircuitId::ConfidentialEddsa(
                u8::try_from(published_inputs).expect("inputs fit u8"),
                u8::try_from(OUTPUTS).expect("outputs fit u8"),
                N_PUBLIC_SLOTS as u8,
            ),
            proof: TransactProof::zeroed(),
            inputs,
            tree_contexts: (0..MAX_INPUT_TREES)
                .map(|_| TreeContext {
                    utxo_tree_root_index: u16::MAX,
                    nullifier_tree_root_index: u16::MAX,
                })
                .collect(),
        },
    };
    transaction_size(
        &payer,
        &[transact.instruction()],
        ComputeBudgetConfig::new(1_400_000).with_priority_fee(u64::MAX),
    )
    .expect("measure the spend")
}

/// Wallet selection pads with random dummies, so a selection of `n` notes
/// publishes the full width of the cheapest shape holding them.
fn published_width(selected: usize) -> usize {
    canonical_shape(selected, OUTPUTS)
        .expect("a shape holds the selection")
        .n_inputs()
}

#[test]
fn max_spend_inputs_is_the_widest_selection_that_always_fits() {
    let at_cap = widest_wallet_spend(published_width(MAX_SPEND_INPUTS));
    assert!(
        at_cap.fits(),
        "{MAX_SPEND_INPUTS} notes: {} bytes, {} addresses",
        at_cap.bytes,
        at_cap.addresses
    );
    let above_cap = widest_wallet_spend(published_width(MAX_SPEND_INPUTS + 1));
    assert!(
        !above_cap.fits(),
        "{} notes still fit: {} bytes, {} addresses",
        MAX_SPEND_INPUTS + 1,
        above_cap.bytes,
        above_cap.addresses
    );
}
