//! Build, decrypt and prove each transfer-matrix case through the current API.

use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_client::Rpc;
use zolana_event::OutputDataEncoding;
use zolana_interface::{N_PUBLIC_SLOTS, SOL_ASSET_FIELD};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::transact::{
        asset_field, signed_magnitude_to_field, ConfidentialTransaction, SettlementTransfer, Shape,
    },
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    Data, Mint, Utxo,
};

use crate::{
    authority_fixture::complete_inputs,
    harness::{asset_addr, random_blinding, Asset, TransferHarness, SPL_ASSET_ID},
    input_fixture::wallet_utxo,
    prover::prove_and_verify_eddsa,
    test_indexer::TestIndexer,
    transfer_fixture::transfer_prover,
};

fn mint(asset: Asset) -> Mint {
    Mint {
        asset: asset_addr(asset),
        asset_id: if asset == Asset::Sol { 1 } else { SPL_ASSET_ID },
    }
}

impl TransferHarness {
    pub(crate) fn prove_and_verify(&self) {
        let mut rng = rand::thread_rng();
        let mut keypair = || {
            ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&random_blinding(
                &mut rng,
            )))
            .unwrap()
        };
        let sender = keypair();
        let owners: Vec<_> = self.plan.inputs.iter().map(|_| keypair()).collect();
        let recipients: Vec<_> = self.plan.sends.iter().map(|_| keypair()).collect();
        let keys: Vec<_> = owners
            .iter()
            .map(|owner| owner.nullifier_key.clone())
            .collect();
        let mut indexer = TestIndexer::new();
        let inputs = self
            .plan
            .inputs
            .iter()
            .zip(&owners)
            .map(|(spec, owner)| {
                let mut input = wallet_utxo(
                    Utxo {
                        owner: owner.signing_pubkey(),
                        asset: mint(spec.asset),
                        amount: spec.amount,
                        blinding: zolana_keypair::random_blinding(),
                        ring_program_id: None,
                        data: Data::default(),
                    },
                    &owner.nullifier_key,
                    0,
                    0,
                    None,
                    None,
                );
                input.leaf_index = indexer.add_utxo(input.utxo_hash);
                input
            })
            .collect();
        let mut tx = ConfidentialTransaction::new(inputs, Address::default()).unwrap();
        let mut expected = Vec::new();
        for (send, recipient) in self.plan.sends.iter().zip(&recipients) {
            let address = recipient.shielded_address().unwrap();
            if send.asset == Asset::Sol {
                tx.transfer_sol(&address, send.amount).unwrap();
            } else {
                tx.transfer(&address, asset_addr(send.asset), send.amount)
                    .unwrap();
            }
            expected.push((address, mint(send.asset), send.amount));
        }
        let mut settlements = Vec::new();
        if let Some(withdraw) = &self.plan.withdraw {
            let recipient = Address::new_from_array([7; 32]);
            if withdraw.asset == Asset::Sol {
                tx.withdraw_sol(withdraw.amount, recipient).unwrap();
                settlements.push(SettlementTransfer::Sol {
                    is_deposit: false,
                    amount: withdraw.amount,
                    user_sol_account: recipient,
                });
            } else {
                tx.withdraw(asset_addr(withdraw.asset), withdraw.amount, recipient)
                    .unwrap();
                settlements.push(SettlementTransfer::Spl {
                    mint: asset_addr(withdraw.asset),
                    is_deposit: false,
                    amount: withdraw.amount,
                    user_spl_token: recipient,
                });
            }
        }
        let mut seen = Vec::new();
        for input in &self.plan.inputs {
            if seen.contains(&input.asset) {
                continue;
            }
            seen.push(input.asset);
            let available: u64 = self
                .plan
                .inputs
                .iter()
                .filter(|i| i.asset == input.asset)
                .map(|i| i.amount)
                .sum();
            let sent: u64 = self
                .plan
                .sends
                .iter()
                .filter(|o| o.asset == input.asset)
                .map(|o| o.amount)
                .sum();
            let withdrawn = self
                .plan
                .withdraw
                .as_ref()
                .filter(|w| w.asset == input.asset)
                .map_or(0, |w| w.amount);
            let change = available - sent - withdrawn;
            if change > 0 {
                expected.push((
                    sender.shielded_address().unwrap(),
                    mint(input.asset),
                    change,
                ));
            }
        }
        if self.plan.declared_shape {
            tx.pad_utxos(Shape::IN2_OUT3, &sender.shielded_address().unwrap())
                .unwrap();
        }
        let tx = tx.encrypt(&sender).unwrap();
        let shape = tx.check_shape().unwrap();
        assert_eq!(tx.input_utxos.len(), shape.n_inputs());
        assert_eq!(tx.output_utxos.len(), shape.n_outputs());
        while expected.len() < shape.n_outputs() {
            expected.push((sender.shielded_address().unwrap(), Mint::SOL, 0));
        }
        let first_nullifier = tx.first_nullifier().unwrap();
        let seed = derive_output_blinding_seed(&first_nullifier, &tx.blinding_seed).unwrap();
        let tx_key = sender
            .get_transaction_viewing_key(&first_nullifier)
            .unwrap();
        for (slot, ((output, encoded), (owner, asset, amount))) in tx
            .output_utxos
            .iter()
            .zip(&tx.external_data.outputs)
            .zip(expected)
            .enumerate()
        {
            let blinding =
                derive_transact_output_blinding(&first_nullifier, &seed, slot as u32).unwrap();
            assert_eq!(
                (
                    output.owner_address,
                    output.asset,
                    output.amount,
                    output.blinding
                ),
                (Some(owner), asset, amount, blinding)
            );
            assert_eq!(encoded.utxo_hash, output.hash(tx.output_tree_id).unwrap());
            assert_eq!(
                tx.external_data.resolved_owner_tags[slot],
                owner.signing_pubkey.confidential_view_tag().unwrap()
            );
            let OutputDataEncoding::Encrypted(blob) =
                OutputDataEncoding::try_from_slice(encoded.data.as_ref().unwrap()).unwrap()
            else {
                panic!("encrypted output expected")
            };
            let body = &blob[1..];
            assert_eq!(
                Confidential::embedded_viewing_pk(body).unwrap(),
                owner.viewing_pubkey
            );
            assert_eq!(
                Confidential::decrypt_with_tx_key(
                    &tx_key,
                    body,
                    tx.external_data.salt,
                    slot as u32
                )
                .unwrap(),
                ConfidentialOutputPlaintext {
                    asset_id: asset.asset_id,
                    amount,
                    blinding,
                    ring_program_id: None,
                    data: Data::default(),
                }
            );
        }
        assert_eq!(tx.external_data.interface_transfers, settlements);
        let transfers = tx.public_transfers().unwrap();
        let mut expected_assets = [[0; 32]; N_PUBLIC_SLOTS];
        let mut expected_amounts = [[0; 32]; N_PUBLIC_SLOTS];
        if let Some(withdraw) = &self.plan.withdraw {
            expected_assets[0] = if withdraw.asset == Asset::Sol {
                SOL_ASSET_FIELD
            } else {
                asset_field(&asset_addr(withdraw.asset)).unwrap()
            };
            expected_amounts[0] = signed_magnitude_to_field(false, withdraw.amount);
        }
        assert_eq!(transfers.assets, expected_assets);
        assert_eq!(transfers.amounts, expected_amounts);
        let proofs = indexer
            .get_input_merkle_proofs(&tx.input_utxo_hashes().unwrap(), None)
            .unwrap();
        let dummy = tx
            .dummy_nullifiers()
            .into_iter()
            .map(|nf| indexer.dummy_nullifier_proof(nf))
            .collect::<Vec<_>>();
        let mut result = transfer_prover(tx, &proofs, &dummy).build().unwrap();
        complete_inputs(&mut result.inputs.inputs, &keys);
        prove_and_verify_eddsa(&result);
    }
}
