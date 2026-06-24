//! When/Then steps plus the build-prove-verify operation they drive.
//!
//! `TransferWorld::prove_and_verify` builds the transfer from the accumulated
//! plan, asserts the exact output UTXOs (independently recomputed) and that the
//! encrypted bundle decrypts back to them, resolves proofs via `TestIndexer`, and
//! verifies the proof against the committed vk for whichever rail the inputs
//! select.

use cucumber::{then, when};
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_client::private_transaction::field::{asset_field, signed_to_field};
use zolana_client::{
    CircuitType, PublicAmounts, Rpc, Shape, SpendUtxo, Transaction, WithdrawalTarget,
};
use zolana_keypair::shielded::ShieldedKeypair;
use zolana_keypair::{NullifierKey, P256Pubkey, PublicKey};
use zolana_transaction::transfer::{
    OutputCiphertext, TransferEncryptedUtxos, TransferRecipientPlaintext, TransferSenderPlaintext,
};
use zolana_transaction::utxo::derive_blinding;
use zolana_transaction::{
    AssetRegistry, Data, ExternalData, OutputUtxo, TransactionEncryption, Utxo, SOL_MINT,
};

use crate::prover::{prove_and_verify_eddsa, prove_and_verify_p256};
use crate::test_indexer::TestIndexer;
use crate::world::{
    asset_addr, asset_kind, random_32, random_blinding, spl_mint, Asset, SendSpec, TransferPlan,
    TransferWorld, WithdrawSpec, SPL_ASSET_ID,
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

        let mut tx = Transaction::new(
            sender.shielded_address().expect("sender address"),
            inputs,
            Address::default(),
        );
        if plan.declared_shape {
            tx = tx.with_shape(Shape::new(2, 3));
        }
        for (recipient, send) in recipients.iter().zip(&plan.sends) {
            tx.send(
                &recipient.shielded_address().expect("recipient address"),
                asset_addr(send.asset),
                send.amount,
                recipient.recipient_bootstrap_view_tag(),
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

        let view_tag = sender.get_sender_view_tag(0).expect("sender view tag");
        let owner_pubkey = Pubkey::default();
        let signed = tx
            .sign(owner_pubkey, &sender, &assets, view_tag)
            .expect("sign");

        let commitments = signed.input_commitments().expect("input commitments");
        let first_nullifier = commitments.first().expect("at least one input").nullifier;
        let mut indexer = TestIndexer::new();
        for commitment in &commitments {
            indexer.add_utxo(commitment.utxo_hash);
        }

        let input_merkle_proofs = indexer
            .get_input_merkle_proofs(&commitments)
            .expect("input merkle proofs");
        match signed
            .into_prover(&input_merkle_proofs)
            .expect("into prover")
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
    // empty change placeholder, so the bundle covers one leading slot here.
    let slots: Vec<OutputCiphertext> = external_data
        .output_ciphertexts
        .iter()
        .map(|slot| OutputCiphertext {
            view_tag: slot.view_tag,
            data: slot.data.clone(),
        })
        .collect();
    let tx_viewing_pk = P256Pubkey::from_bytes(external_data.tx_viewing_pk).unwrap();
    let blob = TransferEncryptedUtxos::from_output_ciphertexts(
        tx_viewing_pk,
        external_data.salt,
        &slots,
        1,
    )
    .unwrap();
    let (sender_pt, recipients_pt) = sender
        .viewing_key
        .decrypt_transfer(first_nullifier, &blob)
        .unwrap();
    let seed = sender_pt.blinding_seed;

    let owner_hash = sender.shielded_address().unwrap().owner_hash().unwrap();
    let mut expected = Vec::new();
    // Slots 0 and 1 hold the sender's SPL and SOL change: a real change UTXO when
    // kept, otherwise an empty (owner = 0) UTXO whose blinding still derives from
    // its fixed position.
    expected.push(if change(Asset::Spl) > 0 {
        OutputUtxo {
            owner_hash,
            asset: spl_mint(),
            amount: change(Asset::Spl),
            blinding: derive_blinding(&seed, 0),
            ..Default::default()
        }
    } else {
        OutputUtxo {
            blinding: derive_blinding(&seed, 0),
            ..Default::default()
        }
    });
    expected.push(if change(Asset::Sol) > 0 {
        OutputUtxo {
            owner_hash,
            asset: SOL_MINT,
            amount: change(Asset::Sol),
            blinding: derive_blinding(&seed, 1),
            ..Default::default()
        }
    } else {
        OutputUtxo {
            blinding: derive_blinding(&seed, 1),
            ..Default::default()
        }
    });
    for (i, (recipient, send)) in recipients.iter().zip(&plan.sends).enumerate() {
        expected.push(OutputUtxo {
            owner_hash: recipient.shielded_address().unwrap().owner_hash().unwrap(),
            asset: asset_addr(send.asset),
            amount: send.amount,
            blinding: derive_blinding(&seed, 2 + i as u8),
            ..Default::default()
        });
    }
    // The builder pads to the fixed (2,3) shape: the real outputs are the prefix,
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
            cpi_signer: None,
            tx_viewing_pk: external_data.tx_viewing_pk,
            salt: external_data.salt,
            output_utxo_hashes: external_data.output_utxo_hashes.clone(),
            output_ciphertexts: external_data.output_ciphertexts.clone(),
        }
    );
    assert_eq!(
        external_data.output_ciphertexts.first().unwrap().view_tag,
        sender.get_sender_view_tag(0).unwrap()
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
            // Padded to MAX_RECIPIENTS (1 for the (2,3) shape) with the sender's own
            // viewing key so the bundle is fixed-size and hides the recipient count.
            recipient_viewing_pks: {
                const MAX_RECIPIENTS: usize = 1;
                let mut pks: Vec<P256Pubkey> =
                    recipients.iter().map(|r| r.viewing_pubkey()).collect();
                while pks.len() < MAX_RECIPIENTS {
                    pks.push(sender.viewing_pubkey());
                }
                pks
            },
            spl_data: Data::default(),
            sol_data: Data::default(),
        }
    );
    let expected_recipients: Vec<TransferRecipientPlaintext> = recipients
        .iter()
        .zip(&plan.sends)
        .enumerate()
        .map(|(i, (recipient, send))| TransferRecipientPlaintext {
            owner_pubkey: recipient.signing_pubkey(),
            sender_pubkey: sender.viewing_pubkey(),
            asset_id: match send.asset {
                Asset::Sol => zolana_transaction::SOL_ASSET_ID,
                Asset::Spl => SPL_ASSET_ID,
            },
            amount: send.amount,
            blinding: derive_blinding(&seed, 2 + i as u8),
            data: Data::default(),
        })
        .collect();
    assert_eq!(recipients_pt, expected_recipients);
}
