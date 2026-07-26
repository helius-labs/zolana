//! What `resolve_zone_program_id` does per read path, pinned so the TypeScript
//! port has something to match rather than a reading of the source. The three
//! cases below are the ones the two implementations can disagree on: a refusal,
//! a discarded id, and a rail that resolves nothing at all.

use solana_address::Address;
use zolana_keypair::{constants::BLINDING_LEN, PublicKey, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    data::{OutputData, DataRecord},
    error::TransactionError,
    serialization::{
        anonymous::AnonymousTransferRecipientPlaintext,
        plaintext::{TransferPlaintextRecipient, TransferPlaintextUtxos},
        OwnerCx, Proofless, SplitBundlePlaintext, UtxoSerialization,
    },
    AssetRegistry, SOL_ASSET_ID, TRANSFER_PLAINTEXT,
};

const BLINDING_SEED: [u8; BLINDING_LEN] = [5u8; BLINDING_LEN];

fn zone_data() -> OutputData {
    OutputData::new(vec![DataRecord::ZoneData(vec![1, 2, 3])])
}

fn owner() -> PublicKey {
    ShieldedKeypair::new().expect("keypair").signing_pubkey()
}

#[test]
fn a_reader_with_no_zone_program_refuses_zone_data() {
    let plaintext = TransferPlaintextUtxos {
        type_prefix: TRANSFER_PLAINTEXT,
        blinding_seed: BLINDING_SEED,
        sender: None,
        recipient_slots: vec![TransferPlaintextRecipient {
            owner_pubkey: owner(),
            asset_id: SOL_ASSET_ID,
            amount: 1_000,
            data: zone_data(),
        }],
    };

    assert_eq!(
        plaintext
            .into_utxos(&AssetRegistry::default(), None)
            .unwrap_err(),
        TransactionError::MissingZoneProgramId
    );
}

/// The id is the reader's, not the payload's, so a plaintext that never
/// mentions a zone must not commit to one.
#[test]
fn a_supplied_zone_program_is_dropped_when_there_is_no_zone_data() {
    let assets = AssetRegistry::default();
    let zone = Address::new_from_array([9u8; 32]);

    let recipient = AnonymousTransferRecipientPlaintext {
        owner_pubkey: owner(),
        sender_pubkey: ViewingKey::new().pubkey(),
        asset_id: SOL_ASSET_ID,
        amount: 7,
        blinding: [3u8; BLINDING_LEN],
        data: OutputData::default(),
    }
    .into_utxo(&assets, Some(zone))
    .expect("recipient utxo");
    assert_eq!(recipient.zone_program_id, None);

    let bundle = SplitBundlePlaintext {
        owner_pubkey: owner(),
        num_outputs: 1,
        asset_id: SOL_ASSET_ID,
        asset_amount: 7,
        blinding_seed: BLINDING_SEED,
        data: OutputData::default(),
    }
    .into_utxos(&assets, Some(zone))
    .expect("split utxos");
    assert_eq!(bundle[0].zone_program_id, None);
}

/// The deposit rail carries its own binding, so there is nothing to resolve
/// against and a payload that omits the id keeps its zone data unbound.
#[test]
fn the_proofless_rail_resolves_nothing() {
    use zolana_event::ProoflessOutput;

    let assets = AssetRegistry::default();
    let cx = OwnerCx {
        owner: owner(),
        assets: &assets,
        zone_program_id: None,
    };
    let utxos = Proofless::into_utxos(
        ProoflessOutput {
            owner: [0u8; 32],
            blinding: [3u8; BLINDING_LEN],
            asset: [0u8; 32],
            amount: 1_000,
            data_hash: None,
            utxo_data: None,
            zone_program_id: None,
            zone_data_hash: None,
            zone_data: Some(vec![1, 2, 3]),
            memo: None,
        },
        &cx,
    )
    .expect("proofless utxos");

    assert_eq!(utxos[0].zone_program_id, None);
    assert_eq!(utxos[0].data.zone_data(), Some([1, 2, 3].as_slice()));
}
