//! When/Then steps plus the build-prove-verify operation they drive.
//!
//! `TransferWorld::prove_and_verify` builds the transfer from the accumulated
//! plan, asserts the exact output UTXOs (independently recomputed) and that the
//! encrypted bundle decrypts back to them, resolves proofs via `TestIndexer`, and
//! verifies the proof against the committed vk for whichever rail the inputs
//! select.

use borsh::BorshDeserialize;
use cucumber::{then, when};
use solana_address::Address;
use zolana_client::{CircuitType, PublicAmounts, Rpc, SpendUtxo, Transaction, WithdrawalTarget};
use zolana_event::OutputData;
use zolana_keypair::{shielded::ShieldedKeypair, NullifierKey, P256Pubkey, PublicKey};
use zolana_transaction::{
    instructions::transact::{
        signed_transaction::{asset_field, signed_to_field},
        SENDER_SLOT_COUNT,
    },
    serialization::{
        confidential::{
            ConfidentialRecipient, ConfidentialSenderBundle, TransferRecipientPlaintext,
            TransferSenderPlaintext,
        },
        DecodeCx, UtxoSerialization,
    },
    utxo::derive_blinding,
    AssetRegistry, Data, ExternalData, OutputUtxo, Utxo, SOL_MINT,
};

use crate::{
    prover::{prove_and_verify_eddsa, prove_and_verify_p256},
    test_indexer::TestIndexer,
    world::{
        asset_addr, asset_kind, random_32, random_blinding, spl_mint, Asset, SendSpec,
        TransferPlan, TransferWorld, WithdrawSpec, SPL_ASSET_ID,
    },
};

#[when(expr = "the sender sends {int} {word} to a fresh recipient")]
fn when_sends(world: &mut TransferWorld, amount: u64, asset_word: String) {
    world.plan.sends.push(SendSpec {
        asset: asset_kind(&asset_word),
        amount,
    });
}

#[when(expr = "the sender withdraws {int} {word} to an external account")]
fn when_withdraws(world: &mut TransferWorld, amount: u64, asset_word: String) {
    world.plan.withdraw = Some(WithdrawSpec {
        asset: asset_kind(&asset_word),
        amount,
    });
}

#[then("the proof verifies")]
fn then_proof_verifies(world: &mut TransferWorld) {
    world.prove_and_verify();
}

impl TransferWorld {
    /// Build the transfer described by the plan, assert its output UTXOs and
    /// encrypted bundle, prove it, and verify the proof. The rail is inferred from
    /// input ownership: any P256-owned input takes the P256 rail (signed),
    /// all-Solana inputs take the eddsa rail (unsigned).
    pub(crate) fn prove_and_verify(&self) {
        let plan = &self.plan;
        let mut rng = rand::thread_rng();
        let sender = ShieldedKeypair::new().expect("sender keypair");
        let assets = AssetRegistry::new([(SPL_ASSET_ID, spl_mint())]).expect("asset registry");

        let inputs: Vec<SpendUtxo> = plan
            .inputs
            .iter()
            .map(|input| {
                let owner = match input.owner {
                    crate::world::Owner::P256 => sender.signing_pubkey(),
                    crate::world::Owner::Solana => PublicKey::from_ed25519(&random_32(&mut rng)),
                };
                let utxo = Utxo {
                    owner,
                    asset: asset_addr(input.asset),
                    amount: input.amount,
                    blinding: random_blinding(&mut rng),
                    zone_program_id: None,
                    data: Data::default(),
                };
                match input.owner {
                    crate::world::Owner::P256 => SpendUtxo::from_keypair(utxo, &sender),
                    crate::world::Owner::Solana => SpendUtxo::from_nullifier_key(
                        utxo,
                        &NullifierKey::from_secret(random_blinding(&mut rng)),
                    ),
                }
            })
            .collect();

        // Fresh recipients are created up front so the expected outputs can name them.
        let recipients: Vec<ShieldedKeypair> = plan
            .sends
            .iter()
            .map(|_| ShieldedKeypair::new().expect("recipient keypair"))
            .collect();

        // These feature files are the established (2,3) proof baseline. The
        // dedicated shape sweep covers every other prover/verifier shape.
        let mut tx = Transaction::new(
            sender.shielded_address().expect("sender address"),
            inputs,
            Address::default(),
        )
        .with_shape(zolana_transaction::instructions::transact::Shape::new(2, 3));
        for (recipient, send) in recipients.iter().zip(&plan.sends) {
            tx.send(
                &recipient.shielded_address().expect("recipient address"),
                asset_addr(send.asset),
                send.amount,
            )
            .expect("send");
        }
        if let Some(withdraw) = &plan.withdraw {
            let target = match withdraw.asset {
                Asset::Sol => WithdrawalTarget::Sol {
                    user_sol_account: Address::new_from_array([7u8; 32]),
                },
                Asset::Spl => WithdrawalTarget::Spl {
                    user_spl_token: Address::new_from_array([8u8; 32]),
                    spl_token_interface: Address::new_from_array([9u8; 32]),
                },
            };
            tx.withdraw(asset_addr(withdraw.asset), withdraw.amount, target)
                .expect("withdraw");
        }

        let signed = tx.sign(&sender, &assets).expect("sign");
        if plan.declared_shape {
            assert_eq!(
                signed.shape,
                zolana_transaction::instructions::transact::Shape::new(2, 3)
            );
        }
        let max_recipients = signed.shape.n_outputs - SENDER_SLOT_COUNT;

        let commitments = signed.input_commitments().expect("input commitments");
        let first_nullifier = commitments.first().expect("at least one input").nullifier;
        let mut indexer = TestIndexer::new();
        for commitment in &commitments {
            indexer.add_utxo(commitment.utxo_hash);
        }

        let input_merkle_proofs = indexer
            .get_input_merkle_proofs(&commitments)
            .expect("input merkle proofs");
        match zolana_client::into_prover(signed, &input_merkle_proofs)
            .expect("into prover")
            .circuit
        {
            CircuitType::P256(prover) => {
                assert_outputs(
                    &prover.outputs,
                    &prover.public_amounts,
                    &prover.external_data,
                    plan,
                    &sender,
                    &recipients,
                    &first_nullifier,
                    max_recipients,
                );
                prove_and_verify_p256(&prover.build().expect("build"));
            }
            CircuitType::Eddsa(prover) => {
                assert_outputs(
                    &prover.outputs,
                    &prover.public_amounts,
                    &prover.external_data,
                    plan,
                    &sender,
                    &recipients,
                    &first_nullifier,
                    max_recipients,
                );
                prove_and_verify_eddsa(&prover.build().expect("build"));
            }
        }
    }
}

/// Recompute the expected output UTXOs from the plan and assert the builder
/// produced exactly those, and that the encrypted bundle decrypts back to the same
/// sender change and recipients.
#[allow(clippy::too_many_arguments)]
fn assert_outputs(
    outputs: &[OutputUtxo],
    public_amounts: &PublicAmounts,
    external_data: &ExternalData,
    plan: &TransferPlan,
    sender: &ShieldedKeypair,
    recipients: &[ShieldedKeypair],
    first_nullifier: &[u8; 32],
    max_recipients: usize,
) {
    let net_public = |asset: Asset| -> i128 {
        match &plan.withdraw {
            Some(w) if w.asset == asset => -(w.amount as i128),
            _ => 0,
        }
    };
    let input_sum = |asset: Asset| -> i128 {
        plan.inputs
            .iter()
            .filter(|i| i.asset == asset)
            .map(|i| i.amount as i128)
            .sum()
    };
    let send_sum = |asset: Asset| -> i128 {
        plan.sends
            .iter()
            .filter(|s| s.asset == asset)
            .map(|s| s.amount as i128)
            .sum()
    };
    let change =
        |asset: Asset| -> u64 { (input_sum(asset) + net_public(asset) - send_sum(asset)) as u64 };

    // `output_ciphertexts` is the ix shape ([bundle, recipients / dummies]) with no
    // empty change placeholder, so the bundle covers one leading slot here. Each
    // slot's borsh `OutputData` carries a scheme byte plus the per-scheme ciphertext
    // body; the sender bundle (slot 0) is decoded with the sender's viewing key, and
    // each recipient slot with that recipient's viewing key.
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
    let seed = sender_pt.blinding_seed;

    let owner_addr = sender.shielded_address().unwrap();
    let mut expected = Vec::new();
    // Slots 0 and 1 hold the sender's SPL and SOL change: a real change UTXO when
    // kept, otherwise an empty (owner = None) UTXO whose blinding still derives from
    // its fixed position.
    expected.push(if change(Asset::Spl) > 0 {
        OutputUtxo {
            owner_address: Some(owner_addr),
            asset: spl_mint(),
            amount: change(Asset::Spl),
            blinding: derive_blinding(&seed, 0),
            ..Default::default()
        }
    } else {
        OutputUtxo {
            blinding: derive_blinding(&seed, 0),
            owner_tag: Some(sender.signing_pubkey().confidential_view_tag().unwrap()),
            ..Default::default()
        }
    });
    expected.push(if change(Asset::Sol) > 0 {
        OutputUtxo {
            owner_address: Some(owner_addr),
            asset: SOL_MINT,
            amount: change(Asset::Sol),
            blinding: derive_blinding(&seed, 1),
            ..Default::default()
        }
    } else {
        OutputUtxo {
            blinding: derive_blinding(&seed, 1),
            owner_tag: Some(sender.signing_pubkey().confidential_view_tag().unwrap()),
            ..Default::default()
        }
    });
    for (i, (recipient, send)) in recipients.iter().zip(&plan.sends).enumerate() {
        expected.push(OutputUtxo {
            owner_address: Some(recipient.shielded_address().unwrap()),
            asset: asset_addr(send.asset),
            amount: send.amount,
            blinding: derive_blinding(&seed, 2 + i as u8),
            ..Default::default()
        });
    }
    // The builder pads to the resolved shape: the real outputs are the prefix,
    // and any trailing slots are dummy padding (owner = 0, amount = 0, random
    // blinding), which cannot be asserted by value.
    let real = outputs
        .get(..expected.len())
        .expect("padded outputs include every real slot");
    assert_eq!(real, expected.as_slice());
    let padding = outputs.get(expected.len()..).unwrap_or(&[]);
    assert!(padding.iter().all(|o| o.is_dummy() && o.amount == 0));

    // Public amounts: signed net per asset, with the SPL asset pinned to 0 when
    // there is no public SPL movement.
    assert_eq!(
        public_amounts,
        &PublicAmounts {
            sol: signed_to_field(net_public(Asset::Sol)),
            spl: signed_to_field(net_public(Asset::Spl)),
            asset: if net_public(Asset::Spl) != 0 {
                asset_field(&spl_mint()).unwrap()
            } else {
                [0u8; 32]
            },
        }
    );

    // External data: transact discriminator, withdrawal magnitudes + accounts,
    // everything else defaulted; the random ciphertext is passed through.
    let (user_sol_account, user_spl_token, spl_token_interface) = match &plan.withdraw {
        Some(w) if w.asset == Asset::Sol => (
            Address::new_from_array([7u8; 32]),
            Address::default(),
            Address::default(),
        ),
        Some(_) => (
            Address::default(),
            Address::new_from_array([8u8; 32]),
            Address::new_from_array([9u8; 32]),
        ),
        None => (Address::default(), Address::default(), Address::default()),
    };
    let sol_public = net_public(Asset::Sol);
    let spl_public = net_public(Asset::Spl);
    assert_eq!(
        external_data,
        &ExternalData {
            instruction_discriminator: 0,
            expiry_unix_ts: u64::MAX,
            relayer_fee: 0,
            public_sol_amount: (sol_public != 0).then_some(sol_public as i64),
            public_spl_amount: (spl_public != 0).then_some(spl_public as i64),
            user_sol_account,
            user_spl_token,
            spl_token_interface,
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: external_data.tx_viewing_pk,
            salt: external_data.salt,
            output_utxo_hashes: external_data.output_utxo_hashes.clone(),
            output_ciphertexts: external_data.output_ciphertexts.clone(),
        }
    );
    assert_eq!(
        external_data.output_ciphertexts.first().unwrap().view_tag,
        sender.signing_pubkey().confidential_view_tag().unwrap()
    );

    // The encrypted bundle decrypts to the same sender change and recipients.
    let has_spl = plan.inputs.iter().any(|i| i.asset == Asset::Spl)
        || plan.sends.iter().any(|s| s.asset == Asset::Spl)
        || matches!(plan.withdraw, Some(w) if w.asset == Asset::Spl);
    assert_eq!(
        sender_pt,
        TransferSenderPlaintext {
            owner_pubkey: sender.signing_pubkey(),
            spl_asset_id: if has_spl { SPL_ASSET_ID } else { 0 },
            spl_amount: change(Asset::Spl),
            sol_amount: change(Asset::Sol),
            blinding_seed: seed,
            // Padded to the resolved shape's recipient capacity with the sender's
            // own viewing key so the bundle hides the real recipient count.
            recipient_viewing_pks: {
                let mut pks: Vec<P256Pubkey> =
                    recipients.iter().map(|r| r.viewing_pubkey()).collect();
                while pks.len() < max_recipients {
                    pks.push(sender.viewing_pubkey());
                }
                pks
            },
            spl_data: Data::default(),
            sol_data: Data::default(),
        }
    );
    let expected_recipients: Vec<TransferRecipientPlaintext> = plan
        .sends
        .iter()
        .enumerate()
        .map(|(i, send)| TransferRecipientPlaintext {
            asset_id: match send.asset {
                Asset::Sol => zolana_transaction::SOL_ASSET_ID,
                Asset::Spl => SPL_ASSET_ID,
            },
            amount: send.amount,
            blinding: derive_blinding(&seed, 2 + i as u8),
            zone_program_id: None,
            data: Data::default(),
        })
        .collect();
    assert_eq!(recipients_pt, expected_recipients);
}
