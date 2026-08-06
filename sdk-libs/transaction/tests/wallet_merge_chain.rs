//! A merge chain settles one output for many legs. Every leg seeds its dummy
//! nullifiers from its own first slot, and the settled output's blinding comes
//! from the top leg's, so a reader that treats the whole chain as one leg
//! reconstructs the wrong UTXO and loses the merged funds.

use zolana_event::{encode_output_data, ProoflessOutput};
use zolana_keypair::{
    merge::{merge_dummy_nullifier, merge_output_blinding},
    ShieldedKeypair, ShieldedKeypairTrait,
};
use zolana_transaction::{
    Address, AssetRegistry, Data, LocalWalletAuthority, OutputContext, OutputSlot, ProofInputUtxo,
    ShieldedTransaction, Utxo, Wallet, DEFAULT_TAG_WINDOW, SOL_MINT,
};

/// One leg at each of two levels. The top leg spends the bottom leg's output in
/// its last slot, so it publishes seven nullifiers against the bottom's eight.
const LEVELS: [u8; 2] = [1, 1];
const BOTTOM_SLOTS: usize = 8;
const TOP_SLOTS: usize = 7;
/// One dummy per leg, so the chain spends thirteen real UTXOs.
const REAL_INPUTS: usize = BOTTOM_SLOTS + TOP_SLOTS - 2;

fn deposit(keypair: &ShieldedKeypair, index: u8, amount: u64) -> ShieldedTransaction {
    let mut blinding = [index.wrapping_add(1); 32];
    blinding[0] = 0;
    let owner = keypair.owner_hash().expect("owner hash");
    let utxo_hash = ProofInputUtxo::new(owner, &SOL_MINT, amount, &blinding)
        .expect("proof input utxo")
        .hash()
        .expect("UTXO hash");

    ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: keypair.recipient_bootstrap_view_tag(),
            output_context: OutputContext {
                hash: utxo_hash,
                tree: Address::new_from_array([0u8; 32]),
                leaf_index: u64::from(index),
            },
            payload: encode_output_data(ProoflessOutput {
                owner,
                blinding,
                asset: SOL_MINT.to_bytes(),
                amount,
                data_hash: None,
                utxo_data: None,
                ring_program_id: None,
                ring_data_hash: None,
                ring_data: None,
                memo: None,
            }),
        }],
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: true,
    }
}

#[test]
fn sync_reconstructs_a_two_leg_chain_output() {
    let keypair = ShieldedKeypair::new().expect("shielded keypair");
    let authority = LocalWalletAuthority::new(Address::default(), &keypair);
    let mut wallet = Wallet::new(
        keypair.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");

    let amounts: Vec<u64> = (0..REAL_INPUTS as u64).map(|i| 100 + i).collect();
    let deposits: Vec<ShieldedTransaction> = amounts
        .iter()
        .enumerate()
        .map(|(index, amount)| deposit(&keypair, index as u8, *amount))
        .collect();
    wallet
        .sync(&authority, &deposits, 1, DEFAULT_TAG_WINDOW)
        .expect("sync deposits");
    assert_eq!(wallet.utxos.len(), REAL_INPUTS, "every deposit discovered");

    // The nullifiers in deposit order, which is the order the legs spend them.
    let spent: Vec<[u8; 32]> = deposits
        .iter()
        .map(|tx| {
            let hash = tx.output_slots[0].output_context.hash;
            wallet
                .utxos
                .iter()
                .find(|u| u.output_context.hash == hash)
                .expect("deposit in wallet")
                .nullifier
        })
        .collect();

    let nullifier_key = keypair.nullifier_key();
    // Bottom leg: seven real slots then one dummy. Top leg: six real slots, one
    // dummy, and the chained slot the bottom leg feeds, which publishes nothing.
    let mut nullifiers = spent[..BOTTOM_SLOTS - 1].to_vec();
    nullifiers.push(
        merge_dummy_nullifier(&nullifier_key, &spent[0], BOTTOM_SLOTS as u8 - 1)
            .expect("bottom dummy"),
    );
    let top_first = spent[BOTTOM_SLOTS - 1];
    nullifiers.extend_from_slice(&spent[BOTTOM_SLOTS - 1..]);
    nullifiers.push(
        merge_dummy_nullifier(&nullifier_key, &top_first, TOP_SLOTS as u8 - 1).expect("top dummy"),
    );
    assert_eq!(nullifiers.len(), BOTTOM_SLOTS + TOP_SLOTS);

    let merged = Utxo {
        owner: keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount: amounts.iter().sum(),
        // The top leg produced the settled output, so its first nullifier seeds
        // the blinding.
        blinding: merge_output_blinding(&nullifier_key, &top_first).expect("output blinding"),
        ring_program_id: None,
        data: Data::default(),
    };
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let merged_hash = merged
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .expect("merged hash");

    let chain = ShieldedTransaction {
        slot: 1,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: [0u8; 32],
            output_context: OutputContext {
                hash: merged_hash,
                tree: Address::new_from_array([0u8; 32]),
                leaf_index: REAL_INPUTS as u64,
            },
            // The published chain shape. Without it a reader cannot tell where
            // the top leg's nullifiers start.
            payload: LEVELS.to_vec(),
        }],
        messages: Vec::new(),
        nullifiers,
        proofless: false,
    };
    wallet
        .sync(
            &authority,
            std::slice::from_ref(&chain),
            2,
            DEFAULT_TAG_WINDOW,
        )
        .expect("sync chain");

    let output = wallet
        .utxos
        .iter()
        .find(|u| u.output_context.hash == merged_hash)
        .expect("merged output reconstructed");
    assert_eq!(output.utxo.amount, amounts.iter().sum::<u64>());
    assert!(!output.spent);
    assert_eq!(
        wallet.utxos.iter().filter(|u| u.spent).count(),
        REAL_INPUTS,
        "every real input the chain spent is marked spent"
    );
}
