//! Unit tests for the `ConfidentialTransfer` builder abstraction that do not need the
//! prover server: change derivation, blinding positions, the encrypted-slot
//! round-trip, rail detection, external-data assembly, and the error paths.

// Single source of truth lives in the client crate's tests; included here
// rather than duplicated.
#[path = "../../client/tests/test_indexer.rs"]
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
    AsyncRpc, CircuitType, ClientError, ConfidentialTransfer, MerkleContext, MerkleProof,
    NonInclusionProof, PublicAmounts, Rpc, SpendProof, SppProofInputUtxo, SppProofInputs,
    TransferP256Prover, WithdrawalTarget, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_event::OutputDataEncoding;
use zolana_interface::instruction::instruction_data::transact::{
    OwnerTag, TransactIxData, TransactProof,
};
use zolana_keypair::{shielded::ShieldedKeypair, NullifierKey, P256Pubkey, PublicKey, ViewingKey};
use zolana_transaction::{
    instructions::transact::{spp_proof_inputs::signed_to_field, Shape, SENDER_SLOT_COUNT},
    serialization::{
        confidential::{Confidential, ConfidentialOutputPlaintext},
        DecodeCx, UtxoSerialization,
    },
    utxo::derive_blinding,
    AssetRegistry, Data, ExternalData, OutputContext, SppProofOutputUtxo, TransactionError, Utxo,
    Wallet, WalletUtxo, SOL_ASSET_ID, SOL_MINT,
};
use zolana_wallet::{
    create_transfer, create_withdrawal, sign_shielded_transaction, AnonymousRecipientSlot,
    ApprovalRequest, EncryptedTransfer, LocalWalletAuthority, P256Signature, SyncWalletAuthority,
    TransferParams, WalletAuthority, WithdrawalParams,
};

fn blinding(rng: &mut ThreadRng) -> [u8; 31] {
    let mut b = [0u8; 31];
    rng.fill_bytes(&mut b);
    b
}

fn p256_input(sender: &ShieldedKeypair, amount: u64, rng: &mut ThreadRng) -> SppProofInputUtxo {
    let utxo = Utxo {
        owner: sender.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding: blinding(rng),
        zone_program_id: None,
        data: Data::default(),
    };
    SppProofInputUtxo::new(utxo, sender)
}

fn registry() -> AssetRegistry {
    AssetRegistry::new([]).expect("registry")
}

struct AsyncTestAuthority {
    keypair: ShieldedKeypair,
    approvals: AtomicUsize,
    p256_signatures: AtomicUsize,
}

#[async_trait::async_trait]
impl WalletAuthority for AsyncTestAuthority {
    fn solana_pubkey(&self) -> Address {
        Address::default()
    }

    async fn shielded_address(
        &self,
    ) -> Result<zolana_keypair::shielded::ShieldedAddress, TransactionError> {
        SyncWalletAuthority::shielded_address(&LocalWalletAuthority::new(
            self.solana_pubkey(),
            &self.keypair,
        ))
    }

    async fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError> {
        Ok(vec![self.keypair.viewing_key.clone()])
    }

    async fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> Result<EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_confidential_transfer(
            &LocalWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            first_nullifier,
            outputs,
            assets,
        )
    }

    async fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: [u8; 32],
        sender: &zolana_transaction::serialization::anonymous::AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<zolana_wallet::EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_anonymous_transfer(
            &LocalWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    async fn request_user_approval(
        &self,
        request: ApprovalRequest,
    ) -> Result<(), TransactionError> {
        assert_eq!(request.solana_pubkey, self.solana_pubkey());
        assert!(request.summary.contains("private transaction"));
        self.approvals.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, TransactionError> {
        self.p256_signatures.fetch_add(1, Ordering::SeqCst);
        SyncWalletAuthority::sign_p256(
            &LocalWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            message_hash,
        )
    }

    async fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError> {
        SyncWalletAuthority::spend_nullifier_key(&LocalWalletAuthority::new(
            self.solana_pubkey(),
            &self.keypair,
        ))
    }
}

fn sign(
    transfer: ConfidentialTransfer,
    sender: &ShieldedKeypair,
) -> Result<SppProofInputs, TransactionError> {
    transfer.sign(sender, &registry())
}

fn prover_of(proof_inputs: SppProofInputs) -> TransferP256Prover {
    let mut indexer = TestIndexer::new();
    let commitments = proof_inputs.input_utxo_hashes().expect("commitments");
    for commitment in &commitments {
        indexer.add_utxo(commitment.utxo_hash);
    }
    let input_merkle_proofs = indexer
        .get_input_merkle_proofs(&commitments, None)
        .expect("input merkle proofs");
    match zolana_client::into_prover(proof_inputs, &input_merkle_proofs)
        .expect("into prover")
        .circuit
    {
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

/// Decode every output slot from the sender's side. The unified scheme gives
/// each output position its own ciphertext sealed to that output's viewing
/// pubkey, so the transaction author re-derives the transaction viewing key and
/// decrypts every slot with it at `slot_index == output position`. Change slots
/// (positions below `SENDER_SLOT_COUNT`) that decode are returned as the
/// sender's own outputs; recipient slots (positions at or above it) are returned
/// with the recipient viewing pubkey embedded in the slot. Dummy and zero-value
/// change slots are length-matched random ciphertexts and fail the decrypt.
fn decrypt(
    sender: &ShieldedKeypair,
    first_nullifier: &[u8; 32],
    external_data: &ExternalData,
) -> (
    Vec<ConfidentialOutputPlaintext>,
    Vec<(P256Pubkey, ConfidentialOutputPlaintext)>,
) {
    let tx_key = sender
        .viewing_key
        .get_transaction_viewing_key(first_nullifier)
        .unwrap();
    let mut change = Vec::new();
    let mut recipients = Vec::new();
    for (position, output) in external_data.outputs.iter().enumerate() {
        let Some(data) = output.data.as_ref() else {
            continue;
        };
        let Ok(output_data) = OutputDataEncoding::try_from_slice(data) else {
            continue;
        };
        let blob = match output_data {
            OutputDataEncoding::Encrypted(blob)
            | OutputDataEncoding::VerifiablyEncrypted(blob)
            | OutputDataEncoding::Plaintext(blob) => blob,
        };
        let Some((_scheme, body)) = blob.split_first() else {
            continue;
        };
        let Ok(plaintext) =
            Confidential::decrypt_with_tx_key(&tx_key, body, external_data.salt, position as u32)
        else {
            continue;
        };
        if position < SENDER_SLOT_COUNT {
            change.push(plaintext);
        } else {
            let recipient_pubkey = Confidential::embedded_viewing_pk(body).unwrap();
            recipients.push((recipient_pubkey, plaintext));
        }
    }
    (change, recipients)
}

#[test]
fn transfer_round_trip_outputs_and_slots() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let sender_addr = sender.shielded_address().unwrap();
    let recipient_addr = recipient.shielded_address().unwrap();

    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    )
    .with_shape(Shape::IN2_OUT3);
    transfer
        .send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
        .unwrap();

    let seed = transfer.blinding_seed;
    let proof_inputs = sign(transfer, &sender).unwrap();
    let first_nullifier = proof_inputs
        .input_utxo_hashes()
        .unwrap()
        .first()
        .unwrap()
        .nullifier;
    let prover = prover_of(proof_inputs);
    let (change, recipients) = decrypt(&sender, &first_nullifier, &prover.external_data);

    // Proof outputs: empty SPL slot (position 0), SOL change (position 1), and the
    // recipient (position 2).
    assert_eq!(
        prover.outputs,
        vec![
            SppProofOutputUtxo {
                blinding: derive_blinding(&seed, 0),
                owner_tag: Some(sender.signing_pubkey().confidential_view_tag().unwrap()),
                ..Default::default()
            },
            SppProofOutputUtxo {
                owner_address: Some(sender_addr),
                asset: SOL_MINT,
                amount: 40,
                blinding: derive_blinding(&seed, 1),
                ..Default::default()
            },
            SppProofOutputUtxo {
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
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: prover.external_data.tx_viewing_pk,
            salt: prover.external_data.salt,
            outputs: prover.external_data.outputs.clone(),
            resolved_owner_tags: prover.external_data.resolved_owner_tags.clone(),
            messages: prover.external_data.messages.clone(),
        }
    );
    // The sender's change slot sits at output 0; its resolved owner tag is the
    // sender's view tag regardless of how the wire `OwnerTag` encodes it.
    assert_eq!(
        prover.external_data.resolved_owner_tags.first().copied(),
        Some(sender.signing_pubkey().confidential_view_tag().unwrap())
    );

    // The encrypted slots decrypt back to the sender's SOL change (40) and the
    // recipient (60). The SPL change slot at position 0 is a zero-value dummy, so
    // only the SOL change decodes on the sender side.
    assert_eq!(
        change,
        vec![ConfidentialOutputPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 40,
            blinding: derive_blinding(&seed, 1),
            zone_program_id: None,
            data: Data::default(),
        }]
    );
    assert_eq!(
        recipients,
        vec![(
            recipient.viewing_pubkey(),
            ConfidentialOutputPlaintext {
                asset_id: SOL_ASSET_ID,
                amount: 60,
                blinding: derive_blinding(&seed, 2),
                zone_program_id: None,
                data: Data::default(),
            }
        )]
    );
}

/// A change-only transfer (recipient slot is a dummy) and a one-recipient transfer
/// must be byte-shape-indistinguishable in `outputs`: same output count, same
/// number of ciphertexts, and every ciphertext the same derived length.
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
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().unwrap(),
            vec![p256_input(&sender, 100, &mut rng)],
            Address::default(),
        )
        .with_shape(Shape::IN2_OUT3);
        if with_recipient {
            let recipient = ShieldedKeypair::new().unwrap();
            transfer
                .send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
                .unwrap();
        }
        let proof_inputs = sign(transfer, &sender).unwrap();
        let commitments = proof_inputs.input_utxo_hashes().unwrap();
        let proofs: Vec<SpendProof> = commitments.iter().map(|_| fake_spend_proof(5)).collect();
        zolana_client::assemble(proof_inputs, &proofs)
            .unwrap()
            .with_proof(TransactProof::zeroed_eddsa())
    };

    let change_only = build(false);
    let one_recipient = build(true);

    // The ciphertext lengths of the data-bearing outputs in order. Every output
    // slot carries its own ciphertext now (the two change slots plus the
    // recipient / dummy slot), so all three positions are data-bearing.
    let ciphertext_lens = |ix: &TransactIxData| -> Vec<usize> {
        ix.outputs
            .iter()
            .filter_map(|output| output.data.as_ref().map(|data| data.len()))
            .collect()
    };
    let change_lens = ciphertext_lens(&change_only);
    let recipient_lens = ciphertext_lens(&one_recipient);

    // Both transactions have the same output count and the same number of
    // ciphertexts, so a dummy does not change the observable shape.
    assert_eq!(change_only.outputs.len(), one_recipient.outputs.len());
    assert_eq!(change_lens.len(), 3);
    assert_eq!(change_lens.len(), recipient_lens.len());

    // The dummy slot (change_only) and the real recipient slot (one_recipient) are
    // the same byte length, so neither stands out. The recipient ciphertext length is
    // derived rather than pinned to a constant.
    let recipient_len = *recipient_lens.get(1).expect("recipient slot");
    for lens in [&change_lens, &recipient_lens] {
        for len in lens.get(1..).expect("recipient region") {
            assert_eq!(*len, recipient_len);
        }
    }

    // The SPL-change slot at position 0 is the same length regardless of the
    // recipient count.
    assert_eq!(
        change_lens.first().unwrap(),
        recipient_lens.first().unwrap(),
    );
}

#[test]
fn assemble_carries_ciphertext_and_decrypts() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let recipient_view_tag = recipient.signing_pubkey().confidential_view_tag().unwrap();

    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    )
    .with_shape(Shape::IN2_OUT3);
    transfer
        .send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
        .unwrap();
    let proof_inputs = sign(transfer, &sender).unwrap();

    let commitments = proof_inputs.input_utxo_hashes().unwrap();
    let first_nullifier = commitments.first().unwrap().nullifier;
    let proofs: Vec<SpendProof> = commitments.iter().map(|_| fake_spend_proof(5)).collect();

    let assembled = zolana_client::assemble(proof_inputs, &proofs).unwrap();
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

    // Output 0 is the sender's change slot. The P256-owned sender carries the
    // shared signing key tag, resolved on-chain from `p256_signing_pk_x` (the
    // sender's view tag); its ciphertext is non-empty. The recipient slot holds
    // the recipient's inline owner tag and a non-empty ciphertext.
    let sender_slot = ix.outputs.first().expect("sender change slot");
    assert_eq!(sender_slot.owner_tag, OwnerTag::P256SigningKey);
    assert_eq!(
        ix.p256_signing_pk_x,
        Some(sender.signing_pubkey().confidential_view_tag().unwrap())
    );
    assert!(sender_slot
        .data
        .as_ref()
        .is_some_and(|data| !data.is_empty()));
    let recipient_slot = ix
        .outputs
        .get(1..)
        .expect("recipient region")
        .iter()
        .find(|output| output.owner_tag == OwnerTag::Inline(recipient_view_tag))
        .expect("recipient slot present");
    assert!(recipient_slot
        .data
        .as_ref()
        .is_some_and(|data| !data.is_empty()));

    // The per-output ciphertext slots decrypt back to the original transfer: the
    // sender decodes its SOL change (position 1) with the transaction viewing
    // key, and the recipient decodes its own slot (position 2). Every slot now
    // carries its own ciphertext, so the AES slot index equals the output
    // position.
    let tx_viewing_pk = P256Pubkey::from_bytes(ix.tx_viewing_pk).unwrap();
    let ciphertexts: Vec<Vec<u8>> = ix
        .outputs
        .iter()
        .filter_map(|output| output.data.clone())
        .collect();
    let slot_body = |slot_index: usize| -> Vec<u8> {
        let data = ciphertexts.get(slot_index).unwrap();
        let output_data = OutputDataEncoding::try_from_slice(data).unwrap();
        let blob = match output_data {
            OutputDataEncoding::Encrypted(blob)
            | OutputDataEncoding::VerifiablyEncrypted(blob)
            | OutputDataEncoding::Plaintext(blob) => blob,
        };
        let (_scheme, body) = blob.split_first().expect("scheme byte plus body");
        body.to_vec()
    };
    let tx_key = sender
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let sender_change =
        Confidential::decrypt_with_tx_key(&tx_key, &slot_body(1), ix.salt, 1).unwrap();
    let recipient_pt = Confidential::decode(
        &slot_body(2),
        &DecodeCx {
            viewing_key: &recipient.viewing_key,
            tx_viewing_pk: Some(tx_viewing_pk),
            salt: Some(ix.salt),
            slot_index: 2,
            first_nullifier: Some(first_nullifier),
        },
    )
    .unwrap();
    assert_eq!(sender_change.amount, 40);
    assert_eq!(recipient_pt.amount, 60);
    assert_eq!(recipient_pt.asset_id, SOL_ASSET_ID);
}

#[test]
fn withdrawal_sets_external_data_and_change() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let sender_addr = sender.shielded_address().unwrap();
    let dest = Address::new_from_array([9u8; 32]);

    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    )
    .with_shape(Shape::IN2_OUT3);
    transfer
        .withdraw(
            SOL_MINT,
            30,
            WithdrawalTarget::Sol {
                user_sol_account: dest,
            },
        )
        .unwrap();

    let seed = transfer.blinding_seed;
    let proof_inputs = sign(transfer, &sender).unwrap();
    let first_nullifier = proof_inputs
        .input_utxo_hashes()
        .unwrap()
        .first()
        .unwrap()
        .nullifier;
    let prover = prover_of(proof_inputs);
    let (change, recipients) = decrypt(&sender, &first_nullifier, &prover.external_data);

    // Slots 0 and 1 are the sender's change (empty SPL, 70 SOL), both with
    // position-derived blinding. Slot 2 is dummy padding to the (2,3) shape with a
    // random blinding, so it is checked structurally rather than by value.
    assert_eq!(prover.outputs.len(), 3);
    assert_eq!(
        prover.outputs.first().unwrap(),
        &SppProofOutputUtxo {
            blinding: derive_blinding(&seed, 0),
            owner_tag: Some(sender.signing_pubkey().confidential_view_tag().unwrap()),
            ..Default::default()
        }
    );
    assert_eq!(
        prover.outputs.get(1).unwrap(),
        &SppProofOutputUtxo {
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
    // The sender's SOL change (70) decodes on the sender side; the zero-value SPL
    // change and the dummy padding do not, and there are no recipients.
    assert_eq!(
        change,
        vec![ConfidentialOutputPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 70,
            blinding: derive_blinding(&seed, 1),
            zone_program_id: None,
            data: Data::default(),
        }]
    );
    assert!(recipients.is_empty());
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
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: prover.external_data.tx_viewing_pk,
            salt: prover.external_data.salt,
            outputs: prover.external_data.outputs.clone(),
            resolved_owner_tags: prover.external_data.resolved_owner_tags.clone(),
            messages: prover.external_data.messages.clone(),
        }
    );
}

#[test]
fn rail_follows_input_owner_type() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();

    let p256_transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 10, &mut rng)],
        Address::default(),
    );
    assert!(p256_transfer.requires_p256_owner().unwrap());

    let ed_utxo = Utxo {
        owner: PublicKey::from_ed25519(&[1u8; 32]),
        asset: SOL_MINT,
        amount: 10,
        blinding: blinding(&mut rng),
        zone_program_id: None,
        data: Data::default(),
    };
    let ed_input = SppProofInputUtxo::new(ed_utxo, NullifierKey::from_secret(blinding(&mut rng)));
    let ed_transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![ed_input],
        Address::default(),
    );
    assert!(!ed_transfer.requires_p256_owner().unwrap());

    let proof_inputs = ed_transfer.sign(&sender, &registry()).unwrap();
    let mut indexer = TestIndexer::new();
    let commitments = proof_inputs.input_utxo_hashes().unwrap();
    for commitment in &commitments {
        indexer.add_utxo(commitment.utxo_hash);
    }
    let input_merkle_proofs = indexer.get_input_merkle_proofs(&commitments, None).unwrap();
    assert!(matches!(
        zolana_client::into_prover(proof_inputs, &input_merkle_proofs)
            .unwrap()
            .circuit,
        CircuitType::Eddsa(_)
    ));
}

#[test]
fn p256_owner_signature_matches_built_private_tx_hash() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    transfer
        .send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
        .unwrap();
    let proof_inputs = sign(transfer, &sender).unwrap();
    let prover = prover_of(proof_inputs);
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
fn input_commitments_include_data_and_zone_hashes() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();
    let mut spend = p256_input(&sender, 100, &mut rng);
    spend.data_hash = Some([11u8; 32]);
    spend.zone_data_hash = Some([12u8; 32]);
    let nullifier_pubkey = spend.nullifier_key.pubkey().unwrap();
    let expected_hash = spend
        .utxo
        .hash(
            &nullifier_pubkey,
            spend.data_hash.as_ref().unwrap(),
            spend.zone_data_hash.as_ref().unwrap(),
        )
        .unwrap();
    let expected_nullifier = spend
        .nullifier_key
        .nullifier(&expected_hash, &spend.utxo.blinding)
        .unwrap();
    let mut tx = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![spend],
        Address::default(),
    );
    tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 60)
        .unwrap();
    let signed = sign(tx, &sender).unwrap();

    let commitments = signed.input_utxo_hashes().unwrap();

    assert_eq!(commitments[0].utxo_hash, expected_hash);
    assert_eq!(commitments[0].nullifier, expected_nullifier);
}

#[test]
fn async_authority_signs_p256_and_invokes_approval() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let authority = AsyncTestAuthority {
        keypair: sender.clone(),
        approvals: AtomicUsize::new(0),
        p256_signatures: AtomicUsize::new(0),
    };
    let spend = p256_input(&sender, 100, &mut rng);
    let nullifier_pk = spend.nullifier_key.pubkey().expect("nullifier pubkey");
    let hash = spend
        .utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .expect("utxo hash");
    let nullifier = spend
        .nullifier_key
        .nullifier(&hash, &spend.utxo.blinding)
        .expect("nullifier");
    let mut wallet = Wallet::new(
        sender.shielded_address().expect("shielded address"),
        registry(),
    )
    .expect("wallet");
    wallet.utxos.push(WalletUtxo {
        utxo: spend.utxo,
        output_context: OutputContext {
            hash,
            tree: Address::default(),
            leaf_index: 0,
        },
        nullifier,
        data_hash: None,
        zone_data_hash: None,
        spent: false,
    });
    let unsigned = create_withdrawal(WithdrawalParams {
        wallet: &wallet,
        payer: Address::default(),
        recipient: Pubkey::new_unique(),
        asset: SOL_MINT,
        amount: 60,
    })
    .expect("created")
    .transaction;
    let signed =
        futures::executor::block_on(sign_shielded_transaction(unsigned, &wallet, &authority))
            .unwrap();

    assert_eq!(authority.approvals.load(Ordering::SeqCst), 1);
    assert_eq!(authority.p256_signatures.load(Ordering::SeqCst), 1);
    let prover = prover_of(signed.transaction);
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
    let transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![],
        Address::default(),
    );
    assert!(matches!(
        sign(transfer, &sender),
        Err(TransactionError::NoInputs)
    ));
}

#[test]
fn oversend_is_insufficient_balance() {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().unwrap();
    let recipient = ShieldedKeypair::new().unwrap();

    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    transfer
        .send(&recipient.shielded_address().unwrap(), SOL_MINT, 200)
        .unwrap();
    match sign(transfer, &sender) {
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
    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    transfer
        .withdraw(
            SOL_MINT,
            10,
            WithdrawalTarget::Sol {
                user_sol_account: Address::default(),
            },
        )
        .unwrap();
    assert!(matches!(
        transfer.withdraw(
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

    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address().unwrap(),
        vec![p256_input(&sender, 100, &mut rng)],
        Address::default(),
    );
    transfer
        .send(
            &ra.shielded_address().unwrap(),
            Address::new_from_array([2u8; 32]),
            1,
        )
        .unwrap();
    transfer
        .send(
            &rb.shielded_address().unwrap(),
            Address::new_from_array([3u8; 32]),
            1,
        )
        .unwrap();
    assert!(matches!(
        sign(transfer, &sender),
        Err(TransactionError::MultiplePublicSplAssets)
    ));
}

#[tokio::test]
async fn create_transfer_builds_withdrawal_when_recipient_unregistered() {
    use solana_account::Account;
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{Data, Utxo, WalletUtxo, SOL_MINT};

    struct RegistryAbsent;

    impl Rpc for RegistryAbsent {
        fn get_account(&self, _address: Address) -> Result<Option<Account>, ClientError> {
            Ok(None)
        }
    }

    #[async_trait::async_trait]
    impl AsyncRpc for RegistryAbsent {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Rpc::get_account(self, address)
        }
    }

    let sender = ShieldedKeypair::new().unwrap();
    let mut wallet = Wallet::new(
        sender.shielded_address().expect("shielded address"),
        registry(),
    )
    .expect("wallet");
    let utxo = Utxo {
        owner: sender.signing_pubkey(),
        asset: SOL_MINT,
        amount: 10,
        blinding: [7u8; 31],
        zone_program_id: None,
        data: Data::default(),
    };
    let nullifier_pk = sender.nullifier_key.pubkey().expect("nullifier pubkey");
    let hash = utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .expect("utxo hash");
    let nullifier = utxo
        .nullifier(&hash, &sender.nullifier_key)
        .expect("nullifier");
    wallet.utxos.push(WalletUtxo {
        utxo,
        output_context: OutputContext {
            hash,
            tree: Address::default(),
            leaf_index: 0,
        },
        nullifier,
        data_hash: None,
        zone_data_hash: None,
        spent: false,
    });

    let recipient = Pubkey::new_unique();
    let rpc = RegistryAbsent;
    let created = create_transfer(TransferParams {
        rpc: &rpc,
        wallet: &wallet,
        payer: Address::default(),
        recipient,
        asset: SOL_MINT,
        amount: 1,
    })
    .await
    .expect("async create transfer");

    assert!(created.recipient.is_public_withdrawal());
    assert_eq!(created.transaction.tree(), Address::default());
}
