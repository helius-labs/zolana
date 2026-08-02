//! Transfer proof construction and verification cases.

use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_client::{
    ConfidentialTransfer, NonInclusionProof, ProverVariant, PublicTransfers, Rpc, SppProofInputUtxo,
};
use zolana_event::OutputDataEncoding;
use zolana_interface::{N_PUBLIC_SLOTS, SOL_ASSET_FIELD};
use zolana_keypair::{shielded::ShieldedKeypair, NullifierKey, P256Pubkey, PublicKey, ViewingKey};
use zolana_transaction::{
    instructions::transact::{
        spp_proof_inputs::{asset_field, signed_to_field},
        SettlementTarget, SettlementTransfer, SENDER_SLOT_COUNT,
    },
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    utxo::derive_blinding,
    AssetRegistry, Data, ExternalData, SppProofOutputUtxo, Utxo, SOL_MINT,
};

use crate::{
    harness::{
        asset_addr, random_32, random_blinding, spl_mint, Asset, TransferHarness, TransferPlan,
        SPL_ASSET_ID,
    },
    prover::prove_and_verify_eddsa,
    test_indexer::TestIndexer,
};

impl TransferHarness {
    /// Build the transfer described by the plan, assert its output UTXOs and
    /// encrypted slots, prove it, and verify the proof. The rail is inferred from
    /// input ownership: any P256-owned input takes the P256 rail (signed),
    /// all-Solana inputs take the eddsa rail (unsigned).
    pub(crate) fn prove_and_verify(&self) {
        let plan = &self.plan;
        let mut rng = rand::thread_rng();
        // Post-PR164 the confidential rail is eddsa-only: sender and recipients
        // are ed25519-derived keypairs.
        let sender = ShieldedKeypair::from_ed25519(&random_blinding(&mut rng), ViewingKey::new())
            .expect("eddsa sender keypair");
        let assets = AssetRegistry::new([(SPL_ASSET_ID, spl_mint())]).expect("asset registry");

        let mut first_solana_owner_tag: Option<[u8; 32]> = None;
        let inputs: Vec<SppProofInputUtxo> = plan
            .inputs
            .iter()
            .map(|input| {
                let owner = {
                    let owner = PublicKey::from_ed25519(&random_32(&mut rng));
                    if first_solana_owner_tag.is_none() {
                        first_solana_owner_tag =
                            Some(owner.confidential_view_tag().expect("first owner tag"));
                    }
                    owner
                };
                let utxo = Utxo {
                    owner,
                    asset: asset_addr(input.asset),
                    amount: input.amount,
                    blinding: random_blinding(&mut rng),
                    ring_program_id: None,
                    data: Data::default(),
                };
                SppProofInputUtxo::new(
                    utxo,
                    NullifierKey::from_secret({
                        let mut secret = [0u8; 31];
                        rand::RngCore::fill_bytes(&mut rng, &mut secret);
                        secret
                    }),
                )
            })
            .collect();

        // Post-PR164, dummy and zero-value slots are tagged with the first real
        // input's owner tag (the "dummy owner tag"), not the sender's.
        let dummy_owner_tag = first_solana_owner_tag.expect("solana owner tag captured");

        // Fresh recipients are created up front so the expected outputs can name
        // them. Post-PR164 the confidential rail is eddsa-only, so recipients are
        // ed25519-derived keypairs (P256 recipients are rejected by `send`).
        let recipients: Vec<ShieldedKeypair> = plan
            .sends
            .iter()
            .map(|_| {
                let seed = random_blinding(&mut rng);
                ShieldedKeypair::from_ed25519(&seed, ViewingKey::new())
                    .expect("eddsa recipient keypair")
            })
            .collect();

        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("sender address"),
            inputs,
            Address::default(),
        );
        if plan.declared_shape {
            transfer =
                transfer.with_shape(zolana_transaction::instructions::transact::Shape::IN2_OUT3);
        }
        for (recipient, send) in recipients.iter().zip(&plan.sends) {
            transfer
                .send(
                    &recipient.shielded_address().expect("recipient address"),
                    asset_addr(send.asset),
                    send.amount,
                )
                .expect("send");
        }
        if let Some(withdraw) = &plan.withdraw {
            let target = match withdraw.asset {
                Asset::Sol => SettlementTarget::Sol {
                    user_sol_account: Address::new_from_array([7u8; 32]),
                },
                Asset::Spl => SettlementTarget::Spl {
                    user_spl_token: Address::new_from_array([8u8; 32]),
                    spl_token_interface: Address::new_from_array([9u8; 32]),
                },
            };
            transfer
                .withdraw(asset_addr(withdraw.asset), withdraw.amount, target)
                .expect("withdraw");
        }

        let seed = transfer.blinding_seed;
        let proof_inputs = transfer.sign(&sender, &assets).expect("sign");

        let commitments = proof_inputs.input_utxo_hashes().expect("input commitments");
        let first_nullifier = commitments.first().expect("at least one input").nullifier;
        let mut indexer = TestIndexer::new();
        for commitment in &commitments {
            indexer.add_utxo(commitment.utxo_hash);
        }

        let input_merkle_proofs = indexer
            .get_input_merkle_proofs(&commitments, None)
            .expect("input merkle proofs");
        let dummy_proofs: Vec<NonInclusionProof> = proof_inputs
            .dummy_nullifiers()
            .expect("dummy nullifiers")
            .into_iter()
            .map(|nullifier| indexer.dummy_nullifier_proof(nullifier))
            .collect();
        let output_assertions = OutputAssertions {
            plan,
            sender: &sender,
            recipients: &recipients,
            first_nullifier: &first_nullifier,
            seed,
            dummy_owner_tag,
        };
        // PR164 removed the P256 transact rail; only the eddsa variant remains.
        let ProverVariant::Eddsa(prover) =
            zolana_client::into_prover(proof_inputs, &input_merkle_proofs, &dummy_proofs)
                .expect("into prover")
                .circuit;
        output_assertions.assert_outputs(
            &prover.outputs,
            &prover.public_transfers,
            &prover.external_data,
        );
        prove_and_verify_eddsa(&prover.build().expect("build"));
    }
}

/// Recompute the expected output UTXOs from the plan and assert the builder
/// produced exactly those, and that the encrypted slots decrypt back to the same
/// sender change and recipients.
struct OutputAssertions<'a> {
    plan: &'a TransferPlan,
    sender: &'a ShieldedKeypair,
    recipients: &'a [ShieldedKeypair],
    first_nullifier: &'a [u8; 32],
    seed: [u8; 32],
    dummy_owner_tag: [u8; 32],
}

impl OutputAssertions<'_> {
    fn assert_outputs(
        &self,
        outputs: &[SppProofOutputUtxo],
        public_transfers: &PublicTransfers,
        external_data: &ExternalData,
    ) {
        let plan = self.plan;
        let sender = self.sender;
        let recipients = self.recipients;
        let first_nullifier = self.first_nullifier;
        let seed = self.seed;
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
        let change = |asset: Asset| -> u64 {
            u64::try_from(input_sum(asset) + net_public(asset) - send_sum(asset))
                .expect("plan balances")
        };

        // Every output position carries its own ciphertext sealed to that output's
        // viewing pubkey, so the transaction author re-derives the transaction viewing
        // key and decrypts every slot at `slot_index == output position`. Change slots
        // (positions below `SENDER_SLOT_COUNT`) that decode are the sender's own
        // outputs; recipient slots reveal their embedded viewing pubkey. Zero-value
        // change and dummy padding are length-matched random ciphertexts and fail the
        // decrypt.
        let tx_key = sender
            .viewing_key
            .get_transaction_viewing_key(first_nullifier)
            .unwrap();
        let mut sender_change: Vec<ConfidentialOutputPlaintext> = Vec::new();
        let mut recipients_pt: Vec<(P256Pubkey, ConfidentialOutputPlaintext)> = Vec::new();
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
            let (_scheme, body) = blob.split_first().expect("scheme byte plus body");
            let Ok(plaintext) = Confidential::decrypt_with_tx_key(
                &tx_key,
                body,
                external_data.salt,
                position as u32,
            ) else {
                continue;
            };
            if position < SENDER_SLOT_COUNT {
                sender_change.push(plaintext);
            } else {
                let recipient_pubkey = Confidential::embedded_viewing_pk(body).unwrap();
                recipients_pt.push((recipient_pubkey, plaintext));
            }
        }

        let owner_addr = sender.shielded_address().unwrap();
        let mut expected = Vec::new();
        // Slots 0 and 1 hold the sender's SPL and SOL change: a real change UTXO when
        // kept, otherwise an empty (owner = None) UTXO whose blinding still derives from
        // its fixed position.
        expected.push(if change(Asset::Spl) > 0 {
            SppProofOutputUtxo {
                owner_address: Some(owner_addr),
                asset: spl_mint(),
                amount: change(Asset::Spl),
                blinding: derive_blinding(&seed, 0),
                ..Default::default()
            }
        } else {
            SppProofOutputUtxo {
                blinding: derive_blinding(&seed, 0),
                owner_tag: Some(self.dummy_owner_tag),
                ..Default::default()
            }
        });
        expected.push(if change(Asset::Sol) > 0 {
            SppProofOutputUtxo {
                owner_address: Some(owner_addr),
                asset: SOL_MINT,
                amount: change(Asset::Sol),
                blinding: derive_blinding(&seed, 1),
                ..Default::default()
            }
        } else {
            SppProofOutputUtxo {
                blinding: derive_blinding(&seed, 1),
                owner_tag: Some(self.dummy_owner_tag),
                ..Default::default()
            }
        });
        for (i, (recipient, send)) in recipients.iter().zip(&plan.sends).enumerate() {
            expected.push(SppProofOutputUtxo {
                owner_address: Some(recipient.shielded_address().unwrap()),
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

        // Public movements: one `(asset, net amount)` slot per interface transfer,
        // signed net per asset, idle slots `(0, 0)`. The plan carries at most one
        // withdrawal leg, so slot 0 is the only occupied one.
        let mut expected_assets = [[0u8; 32]; N_PUBLIC_SLOTS];
        let mut expected_amounts = [[0u8; 32]; N_PUBLIC_SLOTS];
        match &plan.withdraw {
            Some(w) if w.asset == Asset::Sol => {
                expected_assets[0] = SOL_ASSET_FIELD;
                expected_amounts[0] = signed_to_field(
                    i64::try_from(net_public(Asset::Sol)).expect("public amount fits i64"),
                );
            }
            Some(_) => {
                expected_assets[0] = asset_field(&spl_mint()).unwrap();
                expected_amounts[0] = signed_to_field(
                    i64::try_from(net_public(Asset::Spl)).expect("public amount fits i64"),
                );
            }
            None => {}
        }
        assert_eq!(
            public_transfers,
            &PublicTransfers {
                assets: expected_assets,
                amounts: expected_amounts,
            }
        );

        // External data: transact discriminator, one resolved settlement leg per
        // interface transfer, everything else defaulted; the random ciphertext is
        // passed through.
        let interface_transfers = match &plan.withdraw {
            Some(w) if w.asset == Asset::Sol => vec![SettlementTransfer::Sol {
                is_deposit: false,
                amount: w.amount,
                user_sol_account: Address::new_from_array([7u8; 32]),
            }],
            Some(w) => vec![SettlementTransfer::Spl {
                mint: spl_mint(),
                is_deposit: false,
                amount: w.amount,
                user_spl_token: Address::new_from_array([8u8; 32]),
                spl_token_interface: Address::new_from_array([9u8; 32]),
            }],
            None => Vec::new(),
        };
        assert_eq!(
            external_data,
            &ExternalData {
                instruction_discriminator: zolana_interface::instruction::tag::TRANSACT,
                expiry_unix_ts: u64::MAX,
                interface_transfers,
                data_hash: None,
                ring_data_hash: None,
                tx_viewing_pk: external_data.tx_viewing_pk,
                salt: external_data.salt,
                outputs: external_data.outputs.clone(),
                resolved_owner_tags: external_data.resolved_owner_tags.clone(),
                messages: external_data.messages.clone(),
            }
        );
        // Post-PR164, zero-value change slots carry the dummy owner tag (the
        // first real input's owner tag); real change slots carry the sender's.
        let sender_tag = sender.signing_pubkey().confidential_view_tag().unwrap();
        for (position, change_amount) in
            [(0usize, change(Asset::Spl)), (1usize, change(Asset::Sol))]
        {
            let want = if change_amount > 0 {
                sender_tag
            } else {
                self.dummy_owner_tag
            };
            assert_eq!(
                external_data.resolved_owner_tags.get(position).copied(),
                Some(want),
                "resolved owner tag at slot {position}"
            );
        }

        // The encrypted slots decrypt to the same sender change and recipients. A
        // change slot decodes on the sender side only when its change is non-zero;
        // zero-value change slots are indistinguishable random dummies.
        let mut expected_change: Vec<ConfidentialOutputPlaintext> = Vec::new();
        if change(Asset::Spl) > 0 {
            expected_change.push(ConfidentialOutputPlaintext {
                asset_id: SPL_ASSET_ID,
                amount: change(Asset::Spl),
                blinding: derive_blinding(&seed, 0),
                ring_program_id: None,
                data: Data::default(),
            });
        }
        if change(Asset::Sol) > 0 {
            expected_change.push(ConfidentialOutputPlaintext {
                asset_id: zolana_transaction::SOL_ASSET_ID,
                amount: change(Asset::Sol),
                blinding: derive_blinding(&seed, 1),
                ring_program_id: None,
                data: Data::default(),
            });
        }
        assert_eq!(sender_change, expected_change);

        let expected_recipients: Vec<(P256Pubkey, ConfidentialOutputPlaintext)> = recipients
            .iter()
            .zip(&plan.sends)
            .enumerate()
            .map(|(i, (recipient, send))| {
                (
                    recipient.viewing_pubkey(),
                    ConfidentialOutputPlaintext {
                        asset_id: match send.asset {
                            Asset::Sol => zolana_transaction::SOL_ASSET_ID,
                            Asset::Spl => SPL_ASSET_ID,
                        },
                        amount: send.amount,
                        blinding: derive_blinding(&seed, 2 + i as u8),
                        ring_program_id: None,
                        data: Data::default(),
                    },
                )
            })
            .collect();
        assert_eq!(recipients_pt, expected_recipients);
    }
}
