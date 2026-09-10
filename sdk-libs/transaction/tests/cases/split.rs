use std::collections::HashSet;

use borsh::BorshDeserialize;
use zolana_keypair::{viewing_key::random_salt, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    data::{Data, DataRecord},
    instructions::{transact::ConfidentialSplit, types::SppProofInputUtxo},
    serialization::{
        split::{Split, SplitBundlePlaintext, SplitEncode, SplitEncryptedUtxos},
        DecodeCx, OwnerCx, UtxoSerialization,
    },
    Address, AssetRegistry, OutputContext, OutputSlot, ShieldedTransaction, TransactionError, Utxo,
    SOL_MINT, SPLIT,
};

use crate::TransactionWorld;

const SPLIT_ASSET_ID: u64 = 2;
const SPLIT_BLINDING_SEED: [u8; 32] = [3u8; 32];
const SPLIT_FIRST_NULLIFIER: [u8; 32] = [11u8; 32];
/// Wire size of a `SplitBundlePlaintext` with empty `data`: 34 B owner pubkey,
/// 1 B `num_outputs`, 8 B `asset_id`, 8 B `asset_amount`, 32 B `blinding_seed`,
/// 1 B empty `data`.
const SPLIT_BUNDLE_PLAINTEXT_LEN: usize = 84;
/// `SplitEncryptedUtxos` around that plaintext: 1 B type prefix, 33 B
/// `tx_viewing_pk`, 16 B salt, 2 B ciphertext length, 84 B ciphertext (no tag).
const SPLIT_INSTRUCTION_DATA_LEN: usize = 136;

pub(crate) fn registry() -> AssetRegistry {
    AssetRegistry::new([(SPLIT_ASSET_ID, Address::new_from_array([5u8; 32]))]).unwrap()
}

pub(crate) fn build_split_tx(
    owner_kp: &zolana_keypair::ShieldedKeypair,
    bundle: &SplitBundlePlaintext,
    first_nullifier: [u8; 32],
) -> ShieldedTransaction {
    let registry = registry();
    let salt = random_salt();
    let tx = owner_kp
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let tx_viewing_pk = tx.pubkey();
    let utxos = bundle
        .clone()
        .into_utxos(&first_nullifier, &registry, None)
        .unwrap();
    let owner_cx = OwnerCx {
        owner: owner_kp.signing_pubkey(),
        assets: &registry,
        ring_program_id: None,
        first_nullifier: Some(first_nullifier),
    };
    let view_tag = owner_kp.get_sender_view_tag(0).unwrap();
    let ciphertext = Split::encode(
        &utxos,
        &owner_cx,
        view_tag,
        &SplitEncode {
            tx: tx.clone(),
            recipient_pubkey: owner_kp.viewing_pubkey(),
            salt,
            slot_index: 0,
            blinding_seed: bundle.blinding_seed,
        },
    )
    .unwrap();

    ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        output_slots: vec![OutputSlot {
            view_tag: ciphertext.view_tag,
            output_context: OutputContext {
                hash: [0u8; 32],
                tree: Default::default(),
                leaf_index: 0,
            },
            payload: ciphertext.data,
        }],
        messages: Vec::new(),
        nullifiers: vec![first_nullifier],
        proofless: false,
    }
}

pub(crate) fn decode_split(
    world: &TransactionWorld,
    owner: &str,
) -> Result<SplitBundlePlaintext, TransactionError> {
    let tx = world.split_tx.as_ref().unwrap();
    let payload = &tx.output_slots.first().expect("split slot").payload;
    let output_data =
        zolana_interface::output_data::OutputDataEncoding::try_from_slice(payload).unwrap();
    let blob = match output_data {
        zolana_interface::output_data::OutputDataEncoding::Encrypted(blob)
        | zolana_interface::output_data::OutputDataEncoding::VerifiablyEncrypted(blob)
        | zolana_interface::output_data::OutputDataEncoding::Plaintext(blob) => blob,
    };
    let body = blob.get(1..).expect("scheme byte");
    let cx = DecodeCx::for_slot(&world.kp(owner).viewing_key, tx, 0);
    Split::decode(body, &cx)
}

pub(crate) fn build_split(
    world: &mut TransactionWorld,
    owner: String,
    num_outputs: u8,
    amount: u64,
) {
    let bundle = SplitBundlePlaintext {
        owner_pubkey: world.kp(&owner).signing_pubkey(),
        num_outputs,
        asset_id: SPLIT_ASSET_ID,
        asset_amount: amount,
        blinding_seed: SPLIT_BLINDING_SEED,
        data: Data::default(),
    };
    assert_eq!(
        bundle.serialize().unwrap().len(),
        SPLIT_BUNDLE_PLAINTEXT_LEN
    );
    let owner_kp = world.fresh_keypair(&owner);
    let tx = build_split_tx(&owner_kp, &bundle, SPLIT_FIRST_NULLIFIER);
    world.sender_name = Some(owner);
    world.split_bundle = Some(bundle);
    world.split_tx = Some(tx);
}

pub(crate) fn split_round_trips(world: &mut TransactionWorld) {
    let tx = world.split_tx.as_ref().unwrap();
    let payload = &tx.output_slots.first().expect("split slot").payload;
    let parsed =
        zolana_interface::output_data::OutputDataEncoding::try_from_slice(payload).unwrap();
    assert_eq!(&borsh::to_vec(&parsed).unwrap(), payload);
}

pub(crate) fn split_blindings(world: &mut TransactionWorld, count: usize) {
    let bundle = world.split_bundle.as_ref().unwrap();
    let blindings = bundle.output_blindings(&SPLIT_FIRST_NULLIFIER).unwrap();
    assert_eq!(blindings.len(), count);
    let mut seen = HashSet::new();
    for blinding in blindings {
        assert!(seen.insert(blinding));
    }
    // The seed alone fixes nothing: a different first nullifier derives a
    // disjoint blinding set.
    let other = bundle.output_blindings(&[12u8; 32]).unwrap();
    for blinding in other {
        assert!(!seen.contains(&blinding));
    }
}

pub(crate) fn split_data_zero_outputs(world: &mut TransactionWorld, owner: String) {
    let registry = AssetRegistry::new([(2, Address::new_from_array([5u8; 32]))]).unwrap();
    let bundle = SplitBundlePlaintext {
        owner_pubkey: world.kp(&owner).signing_pubkey(),
        num_outputs: 0,
        asset_id: 2,
        asset_amount: 0,
        blinding_seed: [3u8; 32],
        data: Data::new(vec![DataRecord::UtxoData(vec![1])]),
    };
    assert_eq!(
        bundle
            .into_utxos(&SPLIT_FIRST_NULLIFIER, &registry, None)
            .unwrap_err(),
        TransactionError::DataWithoutOutput
    );
}

pub(crate) fn split_too_many_outputs_rejected(world: &mut TransactionWorld, owner: String) {
    let bundle = SplitBundlePlaintext {
        owner_pubkey: world.kp(&owner).signing_pubkey(),
        num_outputs: 9,
        asset_id: SPLIT_ASSET_ID,
        asset_amount: 1,
        blinding_seed: [3u8; 32],
        data: Data::default(),
    };
    let bytes = bundle.serialize().unwrap();
    assert_eq!(
        SplitBundlePlaintext::deserialize(&bytes).unwrap_err(),
        TransactionError::SplitInvalidPartCount { num_outputs: 9 }
    );
    assert_eq!(
        bundle.output_blindings(&SPLIT_FIRST_NULLIFIER).unwrap_err(),
        TransactionError::SplitInvalidPartCount { num_outputs: 9 }
    );
}

/// A signed split's slot-0 bundle, decoded with the transaction's first
/// nullifier, rebuilds utxos whose hashes equal the committed output hashes;
/// decoded under any other first nullifier it does not.
pub(crate) fn split_bundle_derives_committed_outputs() {
    // The transact split rail is ed25519-only.
    let keypair = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32]))
        .expect("ed25519 keypair");
    let parts = 4u8;
    let per_output = 250u64;
    let input_utxo = Utxo {
        owner: keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount: per_output * u64::from(parts),
        blinding: [5u8; 32],
        ring_program_id: None,
        data: Data::default(),
    };
    let input = SppProofInputUtxo::new(input_utxo, &keypair);
    let signed = ConfidentialSplit::new(
        keypair.shielded_address().unwrap(),
        input,
        SOL_MINT,
        parts,
        per_output,
        Address::default(),
    )
    .unwrap()
    .sign(&keypair, &AssetRegistry::default())
    .unwrap();
    let first_nullifier = signed.input_utxos.first().unwrap().nullifier().unwrap();

    let payload = signed
        .external_data
        .outputs
        .first()
        .and_then(|slot| slot.data.as_ref())
        .expect("slot-0 bundle");
    let zolana_interface::output_data::OutputDataEncoding::Encrypted(blob) =
        zolana_interface::output_data::OutputDataEncoding::try_from_slice(payload).unwrap()
    else {
        panic!("split bundle must be an encrypted output");
    };
    let body = blob.get(1..).expect("scheme byte");
    let tx_viewing_pk =
        zolana_keypair::P256Pubkey::from_bytes(signed.external_data.tx_viewing_pk).unwrap();
    let cx = DecodeCx {
        viewing_key: &keypair.viewing_key,
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(signed.external_data.salt),
        slot_index: 0,
        first_nullifier: Some(first_nullifier),
    };
    let plaintext = Split::decode(body, &cx).unwrap();
    assert_eq!(
        plaintext.serialize().unwrap().len(),
        SPLIT_BUNDLE_PLAINTEXT_LEN
    );
    // The slot ciphertext is AES-CTR without a tag: as long as the plaintext.
    assert_eq!(body.len(), SPLIT_BUNDLE_PLAINTEXT_LEN);
    let instruction_data = SplitEncryptedUtxos {
        type_prefix: SPLIT,
        tx_viewing_pk,
        salt: signed.external_data.salt,
        ciphertext: body.to_vec(),
    };
    assert_eq!(
        instruction_data.serialize().unwrap().len(),
        SPLIT_INSTRUCTION_DATA_LEN
    );
    assert_eq!(
        plaintext.blinding_seed,
        signed.output_blinding_seed().unwrap()
    );

    let nullifier_pk = keypair.nullifier_key.pubkey().unwrap();
    let zero = [0u8; 32];
    let committed: Vec<[u8; 32]> = signed
        .output_utxos
        .iter()
        .take(usize::from(parts))
        .map(|output| output.hash(signed.output_tree_id).unwrap())
        .collect();

    let assets = AssetRegistry::default();
    let recovered = plaintext
        .clone()
        .into_utxos(&first_nullifier, &assets, None)
        .unwrap();
    let recovered_hashes: Vec<[u8; 32]> = recovered
        .iter()
        .map(|utxo| {
            utxo.hash(&nullifier_pk, &zero, &zero, signed.output_tree_id)
                .unwrap()
        })
        .collect();
    assert_eq!(recovered_hashes, committed);

    let mut wrong_nullifier = first_nullifier;
    wrong_nullifier[31] ^= 1;
    let mismatched = plaintext
        .into_utxos(&wrong_nullifier, &assets, None)
        .unwrap();
    for (utxo, committed) in mismatched.iter().zip(&committed) {
        let hash = utxo
            .hash(&nullifier_pk, &zero, &zero, signed.output_tree_id)
            .unwrap();
        assert_ne!(hash, *committed);
    }
}

pub(crate) fn split_decrypt(world: &mut TransactionWorld, owner: String, count: u8, amount: u64) {
    let bundle = decode_split(world, &owner).unwrap();
    assert_eq!(bundle.num_outputs, count);
    assert_eq!(bundle.asset_amount, amount);
}
