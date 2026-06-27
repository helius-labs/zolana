//! Unit tests for the `Transaction` builder abstraction that do not need the
//! prover server: change derivation, blinding positions, the encrypted-bundle
//! round-trip, rail detection, external-data assembly, and the error paths.

#[path = "test_indexer.rs"]
mod test_indexer;

use std::sync::atomic::{AtomicUsize, Ordering};

use borsh::BorshDeserialize;
use p256::{
    ecdsa::{
        signature::hazmat::PrehashVerifier, Signature as EcdsaSignature,
        VerifyingKey as EcdsaVerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand::{rngs::ThreadRng, RngCore};
use solana_address::Address;
use solana_pubkey::Pubkey;
use test_indexer::TestIndexer;
use zolana_client::{
    sign_transaction, AnonymousRecipientSlot, ApprovalRequest, CircuitType, ClientError,
    ConfidentialRecipientSlot, MerkleContext, MerkleProof, NonInclusionProof, P256Signature,
    PublicAmounts, Rpc, SignedTransaction, SpendProof, SpendUtxo, SyncWalletAuthority, Transaction,
    TransferP256Prover, WalletAuthority, WithdrawalTarget, NULLIFIER_TREE_HEIGHT,
    STATE_TREE_HEIGHT,
};
use zolana_event::OutputData;
use zolana_interface::instruction::instruction_data::transact::TransactProof;
use zolana_keypair::{shielded::ShieldedKeypair, NullifierKey, P256Pubkey, PublicKey};
use zolana_transaction::{
    instructions::transact::signed_transaction::signed_to_field,
    serialization::{
        confidential::{
            ConfidentialRecipient, ConfidentialSenderBundle, TransferRecipientPlaintext,
            TransferSenderPlaintext,
        },
        DecodeCx, UtxoSerialization,
    },
    utxo::derive_blinding,
    AssetRegistry, Data, ExternalData, OutputUtxo, TransactionError, Utxo, SOL_ASSET_ID, SOL_MINT,
};

fn blinding(rng: &mut ThreadRng) -> [u8; 31] {
    let mut b = [0u8; 31];
    rng.fill_bytes(&mut b);
    b
}

fn p256_input(sender: &ShieldedKeypair, amount: u64, rng: &mut ThreadRng) -> SpendUtxo {
    let utxo = Utxo {
        owner: sender.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding: blinding(rng),
        zone_program_id: None,
        data: Data::default(),
    };
    SpendUtxo::from_keypair(utxo, sender)
}

fn registry() -> AssetRegistry {
    AssetRegistry::new([]).expect("registry")
}

struct AsyncTestAuthority {
    keypair: ShieldedKeypair,
    approvals: AtomicUsize,
    p256_signatures: AtomicUsize,
}

#[async_trait::async_trait(?Send)]
impl WalletAuthority for AsyncTestAuthority {
    async fn shielded_address(
        &self,
        owner_pubkey: Pubkey,
    ) -> Result<zolana_keypair::shielded::ShieldedAddress, ClientError> {
        SyncWalletAuthority::shielded_address(&self.keypair, owner_pubkey)
    }

    async fn encrypt_confidential_transfer(
        &self,
        owner_pubkey: Pubkey,
        first_nullifier: &[u8; 32],
        sender_tag: [u8; 32],
        sender: &TransferSenderPlaintext,
        recipients: &[ConfidentialRecipientSlot],
    ) -> Result<zolana_client::EncryptedTransfer, ClientError> {
        SyncWalletAuthority::encrypt_confidential_transfer(
            &self.keypair,
            owner_pubkey,
            first_nullifier,
            sender_tag,
            sender,
            recipients,
        )
    }

    async fn encrypt_anonymous_transfer(
        &self,
        owner_pubkey: Pubkey,
        first_nullifier: &[u8; 32],
        sender_view_tag: [u8; 32],
        sender: &zolana_transaction::serialization::anonymous::AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<zolana_client::EncryptedTransfer, ClientError> {
        SyncWalletAuthority::encrypt_anonymous_transfer(
            &self.keypair,
            owner_pubkey,
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    async fn request_user_approval(&self, request: ApprovalRequest) -> Result<(), ClientError> {
        assert_eq!(request.owner_pubkey, Pubkey::default());
        assert!(request.summary.contains("private transaction"));
        self.approvals.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn sign_p256(
        &self,
        owner_pubkey: Pubkey,
        message_hash: &[u8; 32],
    ) -> Result<P256Signature, ClientError> {
        self.p256_signatures.fetch_add(1, Ordering::SeqCst);
        SyncWalletAuthority::sign_p256(&self.keypair, owner_pubkey, message_hash)
    }

    async fn spend_nullifier_key(&self, owner_pubkey: Pubkey) -> Result<NullifierKey, ClientError> {
        SyncWalletAuthority::spend_nullifier_key(&self.keypair, owner_pubkey)
    }
}

fn sign(tx: Transaction, sender: &ShieldedKeypair) -> Result<SignedTransaction, TransactionError> {
    tx.sign(sender, &registry())
}

fn prover_of(signed: SignedTransaction) -> TransferP256Prover {
    let mut indexer = TestIndexer::new();
    let commitments = signed.input_commitments().expect("commitments");
    for commitment in &commitments {
        indexer.add_utxo(commitment.utxo_hash);
    }
    let input_merkle_proofs = indexer
        .get_input_merkle_proofs(&commitments)
        .expect("input merkle proofs");
    match zolana_client::into_prover(signed, &input_merkle_proofs).expect("into prover") {
        CircuitType::P256(prover) => prover,
        CircuitType::Eddsa(_) => panic!("expected P256 rail"),
    }
}

/// A zero-filled proof of the right path lengths, used to drive `assemble`
/// off-line (witness construction does not verify the paths). `root_index`
/// surfaces in the instruction's `InputUtxo`.
fn fake_spend_proof(root_index: u16) -> SpendProof {
    let context = MerkleContext {
        tree_type: 0,
        tree: Address::default(),
    };
    SpendProof {
        state: MerkleProof {
            leaf: [0u8; 32],
            merkle_context: context.clone(),
            path: vec![[0u8; 32]; STATE_TREE_HEIGHT],
            leaf_index: 0,
            root: [0u8; 32],
            root_seq: 0,
            root_index,
        },
        nullifier: NonInclusionProof {
            leaf: [0u8; 32],
            merkle_context: context,
            path: vec![[0u8; 32]; NULLIFIER_TREE_HEIGHT],
            low_element: [0u8; 32],
            low_element_index: 0,
            high_element: [0u8; 32],
            high_element_index: 0,
            root: [0u8; 32],
            root_seq: 0,
            root_index,
        },
    }
}

/// Decode the sender bundle (slot 0) with the sender's viewing key and each
/// recipient slot (`1 + i`) with that recipient's viewing key. The ix shape is
/// `[bundle, recipients / dummies]` with no empty change placeholder, so the bundle
/// covers one leading slot here.
fn decrypt(
    sender: &ShieldedKeypair,
    recipients: &[&ShieldedKeypair],
    first_nullifier: &[u8; 32],
    external_data: &ExternalData,
) -> (TransferSenderPlaintext, Vec<TransferRecipientPlaintext>) {
    let tx_viewing_pk = P256Pubkey::from_bytes(external_data.tx_viewing_pk).unwrap();
    let slot_body = |slot_index: usize| -> Vec<u8> {
        let slot = external_data.output_ciphertexts.get(slot_index).unwrap();
        let output_data = OutputData::try_from_slice(&slot.data).unwrap();
        let blob = match output_data {
            OutputData::Encrypted(blob)
            | OutputData::VerifiablyEncrypted(blob)
            | OutputData::Plaintext(blob) => blob,
        };
        let (_scheme, body) = blob.split_first().expect("scheme byte plus body");
        body.to_vec()
    };

    let sender_body = slot_body(0);
    let sender_pt = ConfidentialSenderBundle::decode(
        &sender_body,
        &DecodeCx {
            viewing_key: &sender.viewing_key,
            tx_viewing_pk: Some(tx_viewing_pk),
            salt: Some(external_data.salt),
            slot_index: 0,
            first_nullifier: Some(*first_nullifier),
        },
    )
    .unwrap();
    let recipients_pt: Vec<TransferRecipientPlaintext> = recipients
        .iter()
        .enumerate()
        .map(|(i, recipient)| {
            let slot_index = i + 1;
            let body = slot_body(slot_index);
            ConfidentialRecipient::decode(
                &body,
                &DecodeCx {
                    viewing_key: &recipient.viewing_key,
                    tx_viewing_pk: Some(tx_viewing_pk),
                    salt: Some(external_data.salt),
                    slot_index: slot_index as u32,
                    first_nullifier: Some(*first_nullifier),
                },
            )
            .unwrap()
        })
        .collect();
    (sender_pt, recipients_pt)
}

#[test]
fn transfer_round_trip_outputs_and_bundle() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let sender_addr = sender.shielded_address().unwrap();
    let recipient_addr = recipient.shielded_address().unwrap();

    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
        .unwrap();

    let signed = sign(tx, &sender).unwrap();
    let first_nullifier = signed
        .input_commitments()
        .unwrap()
        .first()
        .unwrap()
        .nullifier;
    let prover = prover_of(signed);
    let (sender_pt, recipients_pt) = decrypt(
        &sender,
        &[&recipient],
        &first_nullifier,
        &prover.external_data,
    );
    let seed = sender_pt.blinding_seed;

    // Proof outputs: empty SPL slot (position 0), SOL change (position 1), and the
    // recipient (position 2).
    assert_eq!(
        prover.outputs,
        vec![
            OutputUtxo {
                blinding: derive_blinding(&seed, 0),
                owner_tag: Some(sender.signing_pubkey().confidential_view_tag().unwrap()),
                ..Default::default()
            },
            OutputUtxo {
                owner_address: Some(sender_addr),
                asset: SOL_MINT,
                amount: 40,
                blinding: derive_blinding(&seed, 1),
                ..Default::default()
            },
            OutputUtxo {
                owner_address: Some(recipient_addr),
                asset: SOL_MINT,
                amount: 60,
                blinding: derive_blinding(&seed, 2),
                ..Default::default()
            },
        ]
    );

    // A pure transfer moves no public value.
    assert_eq!(prover.public_amounts, PublicAmounts::transfer());

    // External data: transact discriminator, no public movement, defaulted
    // accounts; the random ciphertext is passed through.
    assert_eq!(
        prover.external_data,
        ExternalData {
            instruction_discriminator: 0,
            expiry_unix_ts: u64::MAX,
            relayer_fee: 0,
            public_sol_amount: None,
            public_spl_amount: None,
            user_sol_account: Address::default(),
            user_spl_token: Address::default(),
            spl_token_interface: Address::default(),
            cpi_signer: None,
            tx_viewing_pk: prover.external_data.tx_viewing_pk,
            salt: prover.external_data.salt,
            output_utxo_hashes: prover.external_data.output_utxo_hashes.clone(),
            output_ciphertexts: prover.external_data.output_ciphertexts.clone(),
        }
    );
    assert_eq!(
        prover.external_data.output_ciphertexts[0].view_tag,
        sender.signing_pubkey().confidential_view_tag().unwrap()
    );

    // The encrypted bundle decrypts back to the sender change + recipient.
    assert_eq!(
        sender_pt,
        TransferSenderPlaintext {
            owner_pubkey: sender.signing_pubkey(),
            spl_asset_id: 0,
            spl_amount: 0,
            sol_amount: 40,
            blinding_seed: seed,
            recipient_viewing_pks: vec![recipient.viewing_pubkey()],
            spl_data: Data::default(),
            sol_data: Data::default(),
        }
    );
    assert_eq!(
        recipients_pt,
        vec![TransferRecipientPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 60,
            blinding: derive_blinding(&seed, 2),
            data: Data::default(),
        }]
    );
}

/// A change-only transfer (recipient slot is a dummy) and a one-recipient transfer
/// must be byte-shape-indistinguishable in `output_ciphertexts`: same slot count,
/// every recipient/dummy slot the same derived ciphertext length, and the same
/// fixed bundle size.
///
/// In the confidential default zone a real recipient slot is tagged by the owner
/// pubkey (a 32-byte value with an arbitrary leading byte). A dummy slot's view tag
/// is the Poseidon hash of 31 random bytes, also a 32-byte value, so a dummy does
/// not stand out by tag length or ciphertext length and the recipient count stays
/// hidden.
#[test]
fn dummy_output_ciphertexts_are_indistinguishable_from_real() {
    let build = |with_recipient: bool| {
        let mut rng = rand::thread_rng();
        let sender = ShieldedKeypair::new().unwrap();
        let mut tx = Transaction::new(
            sender.shielded_address().unwrap(),
            vec![p256_input(&sender, 100, &mut rng)],
            Address::default(),
        );
        if with_recipient {
            let recipient = ShieldedKeypair::new().unwrap();
            tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
                .unwrap();
        }
        let signed = sign(tx, &sender).unwrap();
        let commitments = signed.input_commitments().unwrap();
        let proofs: Vec<SpendProof> = commitments.iter().map(|_| fake_spend_proof(5)).collect();
        zolana_client::assemble(signed, &proofs)
            .unwrap()
            .with_proof(TransactProof::zeroed_eddsa())
    };

    let change_only = build(false);
    let one_recipient = build(true);

    assert_eq!(change_only.output_ciphertexts.len(), 2);
    assert_eq!(
        change_only.output_ciphertexts.len(),
        one_recipient.output_ciphertexts.len(),
    );

    // The dummy slot (change_only) and the real recipient slot (one_recipient) are
    // the same byte length, so neither stands out. The recipient ciphertext length is
    // derived rather than pinned to a constant.
    let recipient_len = one_recipient
        .output_ciphertexts
        .get(1)
        .expect("recipient slot")
        .data
        .len();
    for ix in [&change_only, &one_recipient] {
        for slot in ix.output_ciphertexts.get(1..).expect("recipient region") {
            assert_eq!(slot.data.len(), recipient_len);
        }
    }

    // The sender bundle is the same fixed size regardless of the recipient count.
    assert_eq!(
        change_only.output_ciphertexts.first().unwrap().data.len(),
        one_recipient.output_ciphertexts.first().unwrap().data.len(),
    );
}

#[test]
fn assemble_carries_ciphertext_and_decrypts() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let recipient_view_tag = recipient.signing_pubkey().confidential_view_tag().unwrap();

    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
        .unwrap();
    let signed = sign(tx, &sender).unwrap();

    let commitments = signed.input_commitments().unwrap();
    let first_nullifier = commitments.first().unwrap().nullifier;
    let proofs: Vec<SpendProof> = commitments.iter().map(|_| fake_spend_proof(5)).collect();

    let assembled = zolana_client::assemble(signed, &proofs).unwrap();
    let ix = assembled.with_proof(TransactProof::zeroed_eddsa());

    // The single real input is padded with one mirrored dummy to the (2,3) shape.
    assert_eq!(ix.inputs.len(), 2);
    let real = ix.inputs.first().expect("real input");
    let dummy = ix.inputs.get(1).expect("dummy input");
    assert_eq!(real.nullifier_hash, first_nullifier);
    assert_eq!(real.utxo_tree_root_index, 5);
    // The dummy mirrors the first real input's root index but carries its own
    // distinct nullifier.
    assert_eq!(dummy.utxo_tree_root_index, 5);
    assert_ne!(dummy.nullifier_hash, first_nullifier);

    // A pure transfer moves no public value.
    assert_eq!(ix.public_sol_amount, None);
    assert_eq!(ix.public_spl_amount, None);

    // output_ciphertexts[0] is the sender bundle under the sender's owner-pubkey tag;
    // the recipient slot holds the recipient's owner-pubkey tag and a non-empty
    // ciphertext.
    let bundle = ix.output_ciphertexts.first().expect("bundle slot");
    assert_eq!(
        bundle.view_tag,
        sender.signing_pubkey().confidential_view_tag().unwrap()
    );
    assert!(!bundle.data.is_empty());
    let recipient_slot = ix
        .output_ciphertexts
        .get(1..)
        .expect("recipient region")
        .iter()
        .find(|slot| slot.view_tag == recipient_view_tag)
        .expect("recipient slot present");
    assert!(!recipient_slot.data.is_empty());

    // The per-output ciphertext slots decrypt back to the original transfer (bundle
    // slot 0 decoded by the sender + one recipient slot decoded by the recipient);
    // the ix shape has no empty change placeholder, so the bundle covers one leading
    // slot here.
    let tx_viewing_pk = P256Pubkey::from_bytes(ix.tx_viewing_pk).unwrap();
    let slot_body = |slot_index: usize| -> Vec<u8> {
        let slot = ix.output_ciphertexts.get(slot_index).unwrap();
        let output_data = OutputData::try_from_slice(&slot.data).unwrap();
        let blob = match output_data {
            OutputData::Encrypted(blob)
            | OutputData::VerifiablyEncrypted(blob)
            | OutputData::Plaintext(blob) => blob,
        };
        let (_scheme, body) = blob.split_first().expect("scheme byte plus body");
        body.to_vec()
    };
    let sender_pt = ConfidentialSenderBundle::decode(
        &slot_body(0),
        &DecodeCx {
            viewing_key: &sender.viewing_key,
            tx_viewing_pk: Some(tx_viewing_pk),
            salt: Some(ix.salt),
            slot_index: 0,
            first_nullifier: Some(first_nullifier),
        },
    )
    .unwrap();
    let recipient_pt = ConfidentialRecipient::decode(
        &slot_body(1),
        &DecodeCx {
            viewing_key: &recipient.viewing_key,
            tx_viewing_pk: Some(tx_viewing_pk),
            salt: Some(ix.salt),
            slot_index: 1,
            first_nullifier: Some(first_nullifier),
        },
    )
    .unwrap();
    assert_eq!(sender_pt.sol_amount, 40);
    assert_eq!(recipient_pt.amount, 60);
    assert_eq!(recipient_pt.asset_id, SOL_ASSET_ID);
}

#[test]
fn withdrawal_sets_external_data_and_change() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let sender_addr = sender.shielded_address().unwrap();
    let dest = Address::new_from_array([9u8; 32]);

    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.withdraw(
        SOL_MINT,
        30,
        WithdrawalTarget::Sol {
            user_sol_account: dest,
        },
    )
    .unwrap();

    let signed = sign(tx, &sender).unwrap();
    let first_nullifier = signed
        .input_commitments()
        .unwrap()
        .first()
        .unwrap()
        .nullifier;
    let prover = prover_of(signed);
    let (sender_pt, recipients_pt) = decrypt(&sender, &[], &first_nullifier, &prover.external_data);
    let seed = sender_pt.blinding_seed;

    // Slots 0 and 1 are the sender's change (empty SPL, 70 SOL), both with
    // position-derived blinding. Slot 2 is dummy padding to the (2,3) shape with a
    // random blinding, so it is checked structurally rather than by value.
    assert_eq!(prover.outputs.len(), 3);
    assert_eq!(
        prover.outputs.first().unwrap(),
        &OutputUtxo {
            blinding: derive_blinding(&seed, 0),
            owner_tag: Some(sender.signing_pubkey().confidential_view_tag().unwrap()),
            ..Default::default()
        }
    );
    assert_eq!(
        prover.outputs.get(1).unwrap(),
        &OutputUtxo {
            owner_address: Some(sender_addr),
            asset: SOL_MINT,
            amount: 70,
            blinding: derive_blinding(&seed, 1),
            ..Default::default()
        }
    );
    let padding = prover.outputs.get(2).unwrap();
    assert!(padding.is_dummy());
    assert_eq!(padding.amount, 0);
    assert!(recipients_pt.is_empty());
    assert_eq!(
        prover.public_amounts,
        PublicAmounts {
            sol: signed_to_field(-30),
            spl: [0u8; 32],
            asset: [0u8; 32],
        }
    );
    assert_eq!(
        prover.external_data,
        ExternalData {
            instruction_discriminator: 0,
            expiry_unix_ts: u64::MAX,
            relayer_fee: 0,
            public_sol_amount: Some(-30),
            public_spl_amount: None,
            user_sol_account: dest,
            user_spl_token: Address::default(),
            spl_token_interface: Address::default(),
            cpi_signer: None,
            tx_viewing_pk: prover.external_data.tx_viewing_pk,
            salt: prover.external_data.salt,
            output_utxo_hashes: prover.external_data.output_utxo_hashes.clone(),
            output_ciphertexts: prover.external_data.output_ciphertexts.clone(),
        }
    );
}

#[test]
fn rail_follows_input_owner_type() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();

    let p256_tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 10, &mut rng)],
        Address::default(),
    );
    assert!(p256_tx.requires_p256_owner().unwrap());

    let ed_utxo = Utxo {
        owner: PublicKey::from_ed25519(&[1u8; 32]),
        asset: SOL_MINT,
        amount: 10,
        blinding: blinding(&mut rng),
        zone_program_id: None,
        data: Data::default(),
    };
    let ed_input =
        SpendUtxo::from_nullifier_key(ed_utxo, &NullifierKey::from_secret(blinding(&mut rng)));
    let ed_tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![ed_input],
        Address::default(),
    );
    assert!(!ed_tx.requires_p256_owner().unwrap());

    let signed = ed_tx.sign(&sender, &registry()).unwrap();
    let mut indexer = TestIndexer::new();
    let commitments = signed.input_commitments().unwrap();
    for commitment in &commitments {
        indexer.add_utxo(commitment.utxo_hash);
    }
    let input_merkle_proofs = indexer.get_input_merkle_proofs(&commitments).unwrap();
    assert!(matches!(
        zolana_client::into_prover(signed, &input_merkle_proofs).unwrap(),
        CircuitType::Eddsa(_)
    ));
}

#[test]
fn p256_owner_signature_matches_built_private_tx_hash() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
        .unwrap();
    let signed = sign(tx, &sender).unwrap();
    let prover = prover_of(signed);
    let owner = prover.p256_owner.clone();
    let built = prover.build().unwrap();
    let message_hash = zolana_keypair::hash::sha256(&built.private_tx_hash);
    let public_key = owner.pubkey.to_p256().unwrap();
    let point = public_key.to_encoded_point(false);
    let verifying_key = EcdsaVerifyingKey::from_encoded_point(&point).unwrap();
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&owner.sig_r);
    sig_bytes[32..].copy_from_slice(&owner.sig_s);
    let signature = EcdsaSignature::from_slice(&sig_bytes).unwrap();
    verifying_key
        .verify_prehash(&message_hash, &signature)
        .expect("signature verifies against built private tx hash");
}

#[test]
fn async_authority_signs_p256_and_invokes_approval() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let authority = AsyncTestAuthority {
        keypair: sender.clone(),
        approvals: AtomicUsize::new(0),
        p256_signatures: AtomicUsize::new(0),
    };
    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
        .unwrap();

    let signed = futures::executor::block_on(sign_transaction(
        tx,
        Pubkey::default(),
        &authority,
        &registry(),
    ))
    .unwrap();

    assert_eq!(authority.approvals.load(Ordering::SeqCst), 1);
    assert_eq!(authority.p256_signatures.load(Ordering::SeqCst), 1);
    let prover = prover_of(signed);
    let owner = prover.p256_owner.clone();
    let built = prover.build().unwrap();
    let message_hash = zolana_keypair::hash::sha256(&built.private_tx_hash);
    let public_key = owner.pubkey.to_p256().unwrap();
    let point = public_key.to_encoded_point(false);
    let verifying_key = EcdsaVerifyingKey::from_encoded_point(&point).unwrap();
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&owner.sig_r);
    sig_bytes[32..].copy_from_slice(&owner.sig_s);
    let signature = EcdsaSignature::from_slice(&sig_bytes).unwrap();
    verifying_key
        .verify_prehash(&message_hash, &signature)
        .expect("async authority signature verifies");
}

#[test]
fn sign_without_inputs_is_no_inputs() {
    let sender = ShieldedKeypair::new().unwrap();
    let tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![],
        Address::default(),
    );
    assert!(matches!(sign(tx, &sender), Err(TransactionError::NoInputs)));
}

#[test]
fn oversend_is_insufficient_balance() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();

    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 200)
        .unwrap();
    match sign(tx, &sender) {
        Err(TransactionError::InsufficientBalance {
            requested,
            available,
        }) => assert_eq!((requested, available), (100, 0)),
        _ => panic!("expected InsufficientBalance"),
    }
}

#[test]
fn second_withdraw_is_rejected() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.withdraw(
        SOL_MINT,
        10,
        WithdrawalTarget::Sol {
            user_sol_account: Address::default(),
        },
    )
    .unwrap();
    assert!(matches!(
        tx.withdraw(
            SOL_MINT,
            5,
            WithdrawalTarget::Sol {
                user_sol_account: Address::default(),
            },
        ),
        Err(TransactionError::WithdrawalAlreadySet)
    ));
}

#[test]
fn two_distinct_spl_assets_are_rejected() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let ra = ShieldedKeypair::new().unwrap();
    let rb = ShieldedKeypair::new().unwrap();

    let mut tx = Transaction::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    tx.send(
        &ra.shielded_address().unwrap(),
        Address::new_from_array([2u8; 32]),
        1,
    )
    .unwrap();
    tx.send(
        &rb.shielded_address().unwrap(),
        Address::new_from_array([3u8; 32]),
        1,
    )
    .unwrap();
    assert!(matches!(
        sign(tx, &sender),
        Err(TransactionError::MultiplePublicSplAssets)
    ));
}
