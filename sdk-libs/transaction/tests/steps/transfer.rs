use borsh::BorshDeserialize;
use cucumber::{then, when};
use zolana_keypair::{constants::BLINDING_LEN, viewing_key::random_salt, ShieldedKeypair};
use zolana_transaction::{
    data::{Data, DataRecord},
    serialization::{
        anonymous::{
            AnonymousRecipient, AnonymousRecipientEncode, AnonymousSenderBundle,
            AnonymousSenderEncode, AnonymousTransferRecipientPlaintext,
            AnonymousTransferSenderPlaintext,
        },
        DecodeCx, OwnerCx, UtxoSerialization,
    },
    AssetRegistry, OutputContext, OutputSlot, ShieldedTransaction, Utxo,
};

use crate::TransactionWorld;

const SPL_ASSET_ID: u64 = 2;
const SENDER_BLINDING_SEED: [u8; BLINDING_LEN] = [2u8; BLINDING_LEN];

pub(crate) struct BuiltTransfer {
    pub transaction: ShieldedTransaction,
    pub sender_plaintext: AnonymousTransferSenderPlaintext,
    pub recipient_plaintexts: Vec<AnonymousTransferRecipientPlaintext>,
    pub recipient_utxos: Vec<Utxo>,
    pub change_utxos: Vec<Utxo>,
}

pub(crate) struct RecipientSpec {
    pub keypair: ShieldedKeypair,
    pub amount: u64,
    pub blinding: [u8; BLINDING_LEN],
    pub asset: solana_address::Address,
    pub asset_id: u64,
    pub view_tag: [u8; 32],
    pub data: Data,
}

pub(crate) fn build_anonymous_transfer(
    registry: &AssetRegistry,
    sender_kp: &ShieldedKeypair,
    sender_plaintext: AnonymousTransferSenderPlaintext,
    recipients: &[RecipientSpec],
    first_nullifier: [u8; 32],
    sender_view_tag: [u8; 32],
) -> BuiltTransfer {
    let salt = random_salt();
    let tx = sender_kp
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let tx_viewing_pk = tx.pubkey();

    let bookkeeping_change = sender_plaintext.clone().into_utxos(registry, None).unwrap();

    let mut encode_change = Vec::new();
    if sender_plaintext.spl_amount > 0 {
        encode_change.push(Utxo {
            owner: sender_plaintext.owner_pubkey,
            asset: registry.resolve(sender_plaintext.spl_asset_id).unwrap(),
            amount: sender_plaintext.spl_amount,
            blinding: zolana_transaction::utxo::derive_blinding(&sender_plaintext.blinding_seed, 0),
            zone_program_id: None,
            data: sender_plaintext.spl_data.clone(),
        });
    }
    encode_change.push(Utxo {
        owner: sender_plaintext.owner_pubkey,
        asset: zolana_transaction::SOL_MINT,
        amount: sender_plaintext.sol_amount,
        blinding: zolana_transaction::utxo::derive_blinding(&sender_plaintext.blinding_seed, 1),
        zone_program_id: None,
        data: sender_plaintext.sol_data.clone(),
    });
    let sender_owner_cx = OwnerCx {
        owner: sender_kp.signing_pubkey(),
        assets: registry,
        zone_program_id: None,
    };
    let sender_ciphertext = AnonymousSenderBundle::encode(
        &encode_change,
        &sender_owner_cx,
        sender_view_tag,
        &AnonymousSenderEncode {
            tx: tx.clone(),
            self_pubkey: sender_kp.viewing_pubkey(),
            salt,
            slot_index: 0,
            blinding_seed: sender_plaintext.blinding_seed,
            recipient_viewing_pks: sender_plaintext.recipient_viewing_pks.clone(),
        },
    )
    .unwrap();

    let sender_nullifier_pk = sender_kp.nullifier_key.pubkey().unwrap();
    let sender_change_hash = bookkeeping_change
        .last()
        .map(|utxo| {
            utxo.hash(&sender_nullifier_pk, &[0u8; 32], &[0u8; 32])
                .unwrap()
        })
        .unwrap_or([0u8; 32]);
    let mut output_slots = vec![OutputSlot {
        view_tag: sender_ciphertext.view_tag,
        output_context: OutputContext {
            hash: sender_change_hash,
            tree: Default::default(),
            leaf_index: 0,
        },
        payload: sender_ciphertext.data,
    }];

    let mut recipient_plaintexts = Vec::new();
    let mut recipient_utxos = Vec::new();
    for (i, spec) in recipients.iter().enumerate() {
        let slot_index = (i + 1) as u32;
        let utxo = Utxo {
            owner: spec.keypair.signing_pubkey(),
            asset: spec.asset,
            amount: spec.amount,
            blinding: spec.blinding,
            zone_program_id: None,
            data: spec.data.clone(),
        };
        let recipient_owner_cx = OwnerCx {
            owner: utxo.owner,
            assets: registry,
            zone_program_id: None,
        };
        let ciphertext = AnonymousRecipient::encode(
            core::slice::from_ref(&utxo),
            &recipient_owner_cx,
            spec.view_tag,
            &AnonymousRecipientEncode {
                tx: tx.clone(),
                recipient_pubkey: spec.keypair.viewing_pubkey(),
                sender_pubkey: sender_kp.viewing_pubkey(),
                salt,
                slot_index,
            },
        )
        .unwrap();

        let nullifier_pk = spec.keypair.nullifier_key.pubkey().unwrap();
        let hash = utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
        output_slots.push(OutputSlot {
            view_tag: ciphertext.view_tag,
            output_context: OutputContext {
                hash,
                tree: Default::default(),
                leaf_index: slot_index as u64,
            },
            payload: ciphertext.data,
        });

        let plaintext = AnonymousTransferRecipientPlaintext {
            owner_pubkey: utxo.owner,
            sender_pubkey: sender_kp.viewing_pubkey(),
            asset_id: spec.asset_id,
            amount: spec.amount,
            blinding: spec.blinding,
            data: spec.data.clone(),
        };
        recipient_plaintexts.push(plaintext);
        recipient_utxos.push(utxo);
    }

    let transaction = ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        output_slots,
        nullifiers: vec![first_nullifier],
        proofless: false,
    };

    BuiltTransfer {
        transaction,
        sender_plaintext,
        recipient_plaintexts,
        recipient_utxos,
        change_utxos: bookkeeping_change,
    }
}

fn registry() -> AssetRegistry {
    AssetRegistry::new([(
        SPL_ASSET_ID,
        solana_address::Address::new_from_array([5u8; 32]),
    )])
    .unwrap()
}

fn build(world: &mut TransactionWorld, recipients: Vec<(String, u64, Data)>) {
    let registry = registry();
    let sender_signing = world.sender().signing_pubkey();
    let sender_kp = world.fresh_keypair(world.sender_name.as_ref().unwrap());

    let mut recipient_viewing_pks = Vec::new();
    let mut specs = Vec::new();
    let mut names = Vec::new();
    let spl_mint = registry.resolve(SPL_ASSET_ID).unwrap();
    for (name, amount, data) in &recipients {
        let rkp = world.kp(name);
        recipient_viewing_pks.push(rkp.viewing_pubkey());
        let view_tag = rkp.viewing_key.recipient_bootstrap_view_tag();
        specs.push(RecipientSpec {
            keypair: world.fresh_keypair(name),
            amount: *amount,
            blinding: [1u8; BLINDING_LEN],
            asset: spl_mint,
            asset_id: SPL_ASSET_ID,
            view_tag,
            data: data.clone(),
        });
        names.push(name.clone());
    }

    let sender_plaintext = AnonymousTransferSenderPlaintext {
        owner_pubkey: sender_signing,
        spl_asset_id: SPL_ASSET_ID,
        spl_amount: 50,
        sol_amount: 5,
        blinding_seed: SENDER_BLINDING_SEED,
        recipient_viewing_pks,
        spl_data: Data::default(),
        sol_data: Data::default(),
    };

    let first_nullifier = [7u8; 32];
    let sender_view_tag = sender_kp.get_sender_view_tag(0).unwrap();
    let built = build_anonymous_transfer(
        &registry,
        &sender_kp,
        sender_plaintext,
        &specs,
        first_nullifier,
        sender_view_tag,
    );

    world.sender_plaintext = Some(built.sender_plaintext);
    world.recipient_plaintexts = built.recipient_plaintexts;
    world.recipient_utxos = built.recipient_utxos;
    world.recipient_names = names;
    world.transfer_tx = Some(built.transaction);
    world.first_nullifier = first_nullifier;
}

#[when(expr = "{string} builds a transfer paying {int} to {string}")]
fn build_one(world: &mut TransactionWorld, sender: String, amount: u64, a: String) {
    world.sender_name = Some(sender);
    build(world, vec![(a, amount, Data::default())]);
}

#[when(expr = "{string} builds a transfer paying {int} to {string} and {int} to {string}")]
fn build_two(
    world: &mut TransactionWorld,
    sender: String,
    amount_a: u64,
    a: String,
    amount_b: u64,
    b: String,
) {
    world.sender_name = Some(sender);
    build(
        world,
        vec![
            (a, amount_a, Data::default()),
            (b, amount_b, Data::default()),
        ],
    );
}

#[when(expr = "{string} builds a transfer with no recipients")]
fn build_zero(world: &mut TransactionWorld, sender: String) {
    world.sender_name = Some(sender);
    build(world, vec![]);
}

#[when(expr = "{string} builds a transfer to {string} with program data")]
fn build_with_data(world: &mut TransactionWorld, sender: String, a: String) {
    world.sender_name = Some(sender);
    let data = Data::new(vec![
        DataRecord::ZoneData(vec![10, 11, 12]),
        DataRecord::UtxoData(vec![20, 21]),
    ]);
    build(world, vec![(a, 1000, data)]);
}

fn decode_recipient(
    world: &TransactionWorld,
    name: &str,
    slot: usize,
) -> Result<AnonymousTransferRecipientPlaintext, zolana_transaction::TransactionError> {
    let tx = world.transfer_tx.as_ref().unwrap();
    let slot_index = slot + 1;
    let payload = &tx
        .output_slots
        .get(slot_index)
        .expect("slot present")
        .payload;
    let output_data = zolana_event::OutputDataEncoding::try_from_slice(payload).unwrap();
    let blob = match output_data {
        zolana_event::OutputDataEncoding::Encrypted(blob)
        | zolana_event::OutputDataEncoding::VerifiablyEncrypted(blob)
        | zolana_event::OutputDataEncoding::Plaintext(blob) => blob,
    };
    let body = blob.get(1..).expect("scheme byte");
    let cx = DecodeCx::for_slot(&world.kp(name).viewing_key, tx, slot_index as u32);
    AnonymousRecipient::decode(body, &cx)
}

#[then(expr = "the transfer blob deserializes back unchanged")]
fn blob_round_trips(world: &mut TransactionWorld) {
    let tx = world.transfer_tx.as_ref().unwrap();
    for slot in &tx.output_slots {
        let parsed = zolana_event::OutputDataEncoding::try_from_slice(&slot.payload).unwrap();
        assert_eq!(borsh::to_vec(&parsed).unwrap(), slot.payload);
    }
}

#[then(expr = "{string} recovers the transfer")]
fn sender_recovers(world: &mut TransactionWorld, sender: String) {
    let tx = world.transfer_tx.as_ref().unwrap();
    let payload = &tx.output_slots.first().expect("sender slot").payload;
    let output_data = zolana_event::OutputDataEncoding::try_from_slice(payload).unwrap();
    let blob = match output_data {
        zolana_event::OutputDataEncoding::Encrypted(blob)
        | zolana_event::OutputDataEncoding::VerifiablyEncrypted(blob)
        | zolana_event::OutputDataEncoding::Plaintext(blob) => blob,
    };
    let body = blob.get(1..).expect("scheme byte");
    let cx = DecodeCx::for_slot(&world.kp(&sender).viewing_key, tx, 0);
    let sender_out = AnonymousSenderBundle::decode(body, &cx).unwrap();
    assert_eq!(&sender_out, world.sender_plaintext.as_ref().unwrap());

    let names = world.recipient_names.clone();
    let recipients_out: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(slot, name)| decode_recipient(world, name, slot).unwrap())
        .collect();
    assert_eq!(recipients_out, world.recipient_plaintexts);
}

#[then(expr = "{string} syncs the transfer and reads amount {int}")]
fn recipient_reads(world: &mut TransactionWorld, name: String, amount: u64) {
    let slot = world.slot_of(&name);
    let pt = decode_recipient(world, &name, slot).unwrap();
    assert_eq!(pt.amount, amount);
}

#[then(expr = "the slot view tag of {string} is their bootstrap tag")]
fn slot_view_tag(world: &mut TransactionWorld, name: String) {
    let slot = world.slot_of(&name);
    let tx = world.transfer_tx.as_ref().unwrap();
    let expected = world.kp(&name).viewing_key.recipient_bootstrap_view_tag();
    let entry = tx.output_slots.get(slot + 1).expect("slot present");
    assert_eq!(entry.view_tag, expected);
}

#[then(expr = "a stranger cannot read the slot of {string}")]
fn stranger_cannot(world: &mut TransactionWorld, name: String) {
    let slot = world.slot_of(&name);
    let tx = world.transfer_tx.as_ref().unwrap();
    let slot_index = slot + 1;
    let payload = &tx
        .output_slots
        .get(slot_index)
        .expect("slot present")
        .payload;
    let output_data = zolana_event::OutputDataEncoding::try_from_slice(payload).unwrap();
    let blob = match output_data {
        zolana_event::OutputDataEncoding::Encrypted(blob)
        | zolana_event::OutputDataEncoding::VerifiablyEncrypted(blob)
        | zolana_event::OutputDataEncoding::Plaintext(blob) => blob,
    };
    let body = blob.get(1..).expect("scheme byte");
    let stranger = ShieldedKeypair::new().unwrap();
    let cx = DecodeCx::for_slot(&stranger.viewing_key, tx, slot_index as u32);
    assert!(AnonymousRecipient::decode(body, &cx).is_err());
}

#[then(expr = "{string} recovers the program data")]
fn recover_data(world: &mut TransactionWorld, name: String) {
    let slot = world.slot_of(&name);
    let pt = decode_recipient(world, &name, slot).unwrap();
    assert!(!pt.data.is_empty());
    let expected = world
        .recipient_plaintexts
        .get(slot)
        .expect("recipient present");
    assert_eq!(pt.data, expected.data);
}

#[then(expr = "{string} can read their slot but not the slot of {string}")]
fn recipient_cannot_read_other_slot(world: &mut TransactionWorld, reader: String, other: String) {
    let own = world.slot_of(&reader);
    let other_slot = world.slot_of(&other);
    assert!(decode_recipient(world, &reader, own).is_ok());
    assert!(decode_recipient(world, &reader, other_slot).is_err());
}

#[then(expr = "an extra recipient slot is ignored for {string}")]
fn extra_slot_ignored(world: &mut TransactionWorld, _sender: String) {
    let real_count = world.recipient_names.len();
    let first_name = world
        .recipient_names
        .first()
        .expect("recipient present")
        .clone();
    let pt = decode_recipient(world, &first_name, 0).unwrap();
    assert_eq!(
        pt.amount,
        world.recipient_plaintexts.first().unwrap().amount
    );
    assert_eq!(real_count, world.recipient_plaintexts.len());
}
