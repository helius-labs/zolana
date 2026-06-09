use cucumber::then;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::PublicKey;
use zolana_transaction::asset::AssetRegistry;
use zolana_transaction::data::{Data, DataRecord};
use zolana_transaction::split::SplitBundlePlaintext;
use zolana_transaction::transfer::{RecipientOutput, TransferSenderPlaintext};
use zolana_transaction::utxo::Utxo;
use zolana_transaction::{Address, TransactionEncryption};

use crate::TransactionWorld;

const SPL_ASSET_ID: u64 = 2;

fn spl_mint() -> Address {
    Address::new_from_array([5u8; 32])
}

fn registry() -> AssetRegistry {
    AssetRegistry::new([(SPL_ASSET_ID, spl_mint())])
}

fn input_utxo(owner: PublicKey, asset: Address, amount: u64, seed: u8) -> Utxo {
    Utxo {
        owner,
        asset,
        amount,
        blinding: [seed; BLINDING_LEN],
        zone_program_id: None,
        data: Data::default(),
    }
}

#[then(expr = "a transfer from {string} to {string} round-trips the change and recipient utxos")]
fn standard_transfer_round_trips(world: &mut TransactionWorld, sender: String, recipient: String) {
    let registry = registry();
    let sender = world.kp(&sender);
    let alice = world.kp(&recipient);
    let sender_nullifier_pk = sender.nullifier_key.pubkey().unwrap();

    let input_sol = input_utxo(sender.signing_pubkey(), Address::default(), 1_000_000, 10);
    let input_spl = input_utxo(sender.signing_pubkey(), spl_mint(), 100, 11);
    let sol_nullifier = input_sol
        .nullifier(
            &input_sol
                .hash(&sender_nullifier_pk, &[0u8; 32], &[0u8; 32])
                .unwrap(),
            &sender.nullifier_key,
        )
        .unwrap();
    let spl_nullifier = input_spl
        .nullifier(
            &input_spl
                .hash(&sender_nullifier_pk, &[0u8; 32], &[0u8; 32])
                .unwrap(),
            &sender.nullifier_key,
        )
        .unwrap();
    assert_ne!(sol_nullifier, spl_nullifier);
    let first_nullifier = sol_nullifier;

    let recipient_utxo = Utxo {
        owner: alice.signing_pubkey(),
        asset: spl_mint(),
        amount: 30,
        blinding: [1u8; BLINDING_LEN],
        zone_program_id: None,
        data: Data::new(vec![DataRecord::ProgramData(vec![1, 2, 3])]),
    };
    let recipient_pt = recipient_utxo
        .to_recipient_plaintext(sender.viewing_pubkey(), &registry)
        .unwrap();

    let sender_pt = TransferSenderPlaintext {
        owner_pubkey: sender.signing_pubkey(),
        spl_asset_id: SPL_ASSET_ID,
        spl_amount: 70,
        sol_amount: 999_000,
        blinding_seed: [2u8; BLINDING_LEN],
        recipient_viewing_pks: vec![alice.viewing_pubkey()],
        data: Data::default(),
    };
    let expected_change = sender_pt.clone().into_utxos(&registry).unwrap();
    assert_eq!(expected_change.len(), 2);

    let output = RecipientOutput {
        view_tag: alice.viewing_key.recipient_bootstrap_view_tag(),
        plaintext: recipient_pt,
    };

    let blob = sender
        .viewing_key
        .encrypt_transfer(&first_nullifier, &sender_pt, std::slice::from_ref(&output))
        .unwrap();

    let (recovered_sender, _) = sender
        .viewing_key
        .decrypt_transfer(&first_nullifier, &blob)
        .unwrap();
    assert_eq!(
        recovered_sender.into_utxos(&registry).unwrap(),
        expected_change
    );

    let recovered_recipient = alice
        .viewing_key
        .decrypt_transfer_recipient(&blob, 0)
        .unwrap()
        .into_utxo(&registry)
        .unwrap();
    assert_eq!(recovered_recipient, recipient_utxo);
}

#[then(expr = "a split by {string} round-trips through utxos")]
fn split_round_trips(world: &mut TransactionWorld, name: String) {
    let registry = registry();
    let owner = world.kp(&name);

    let split_pt = SplitBundlePlaintext {
        owner_pubkey: owner.signing_pubkey(),
        num_outputs: 4,
        asset_id: SPL_ASSET_ID,
        asset_amount: 200,
        blinding_seed: [3u8; BLINDING_LEN],
        data: Data::default(),
    };
    let expected = split_pt.clone().into_utxos(&registry).unwrap();
    assert_eq!(expected.len(), 4);

    let nf = [11u8; 32];
    let blob = owner.viewing_key.encrypt_split(&nf, &split_pt).unwrap();
    let recovered = owner
        .viewing_key
        .decrypt_split(&blob)
        .unwrap()
        .into_utxos(&registry)
        .unwrap();

    assert_eq!(recovered, expected);
}
