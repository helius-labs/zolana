//! Spec-driven transfer runner for the BDD scenarios: build a shielded transfer
//! with the `Transaction` builder from a declarative `TransferPlan`, assert the
//! exact output UTXOs (independently recomputed from the plan) and that the
//! encrypted bundle decrypts back to them, resolve state + nullifier proofs via
//! `TestIndexer`, prove on the prover server, and verify against the committed
//! verifying key for whichever rail the inputs select (P256 `transfer_p256_2_3` or
//! Solana-only `transfer_2_3`).

pub mod test_indexer;

use groth16_solana::groth16::Groth16Verifier;
use rand::{rngs::ThreadRng, RngCore};
use solana_address::Address;
use test_indexer::TestIndexer;
use zolana_client::private_transaction::field::{asset_field, signed_to_field};
use zolana_client::{
    spawn_prover, CircuitType, ProverClient, PublicAmounts, RpcBlocking, Shape, SpendUtxo,
    Transaction, TransferP256ProofResult, TransferProofResult, WithdrawalTarget,
};
use zolana_interface::verifying_keys::{transfer_2_3, transfer_p256_2_3};
use zolana_keypair::shielded::ShieldedKeypair;
use zolana_keypair::{NullifierKey, PublicKey};
use zolana_transaction::transfer::{
    TransferEncryptedUtxos, TransferRecipientPlaintext, TransferSenderPlaintext,
};
use zolana_transaction::utxo::derive_blinding;
use zolana_transaction::{
    AssetRegistry, Data, ExternalData, OutputUtxo, TransactionEncryption, Utxo, SOL_MINT,
};

/// Registry id for the single test SPL mint (SOL is the reserved id 1).
const SPL_ASSET_ID: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Owner {
    P256,
    Solana,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Asset {
    Sol,
    Spl,
}

#[derive(Debug, Clone, Copy)]
pub struct InputSpec {
    pub owner: Owner,
    pub asset: Asset,
    pub amount: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct SendSpec {
    pub asset: Asset,
    pub amount: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct WithdrawSpec {
    pub asset: Asset,
    pub amount: u64,
}

#[derive(Debug, Default)]
pub struct TransferPlan {
    pub inputs: Vec<InputSpec>,
    pub sends: Vec<SendSpec>,
    pub withdraw: Option<WithdrawSpec>,
    pub declared_shape: bool,
}

fn random_blinding(rng: &mut ThreadRng) -> [u8; 31] {
    let mut b = [0u8; 31];
    rng.fill_bytes(&mut b);
    b
}

fn random_32(rng: &mut ThreadRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

fn spl_mint() -> Address {
    Address::new_from_array([2u8; 32])
}

fn asset_addr(asset: Asset) -> Address {
    match asset {
        Asset::Sol => SOL_MINT,
        Asset::Spl => spl_mint(),
    }
}

/// Build the transfer described by `plan`, assert its output UTXOs and encrypted
/// bundle, prove it, and verify the proof. The rail is inferred from input
/// ownership: any P256-owned input takes the P256 rail (signed), all-Solana
/// inputs take the eddsa rail (unsigned).
pub fn run(plan: &TransferPlan) {
    let mut rng = rand::thread_rng();
    let sender = ShieldedKeypair::new().expect("sender keypair");
    let assets = AssetRegistry::new([(SPL_ASSET_ID, spl_mint())]).expect("asset registry");

    let inputs: Vec<SpendUtxo> = plan
        .inputs
        .iter()
        .map(|input| {
            let owner = match input.owner {
                Owner::P256 => sender.signing_pubkey(),
                Owner::Solana => PublicKey::from_ed25519(&random_32(&mut rng)),
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
                Owner::P256 => SpendUtxo::from((utxo, &sender)),
                Owner::Solana => SpendUtxo {
                    utxo,
                    nullifier_key: NullifierKey::from_secret(random_blinding(&mut rng)),
                    program_data_hash: None,
                    zone_data_hash: None,
                },
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
    let signed = if tx.requires_p256_owner().expect("rail") {
        tx.sign(&sender, &assets, view_tag).expect("sign")
    } else {
        tx.finalize(&sender, &assets, view_tag).expect("finalize")
    };

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

/// Recompute the expected output UTXOs from the plan and assert the builder
/// produced exactly those, and that the encrypted bundle decrypts back to the
/// same sender change and recipients.
fn assert_outputs(
    outputs: &[OutputUtxo],
    public_amounts: &PublicAmounts,
    external_data: &ExternalData,
    plan: &TransferPlan,
    sender: &ShieldedKeypair,
    recipients: &[ShieldedKeypair],
    first_nullifier: &[u8; 32],
) {
    let blob = TransferEncryptedUtxos::deserialize(&external_data.encrypted_utxos).unwrap();
    let (sender_pt, recipients_pt) = sender
        .viewing_key
        .decrypt_transfer(first_nullifier, &blob)
        .unwrap();
    let seed = sender_pt.blinding_seed;

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

    let owner_hash = sender.shielded_address().unwrap().owner_hash().unwrap();
    let mut expected = Vec::new();
    if change(Asset::Spl) > 0 {
        expected.push(OutputUtxo {
            owner_hash,
            asset: spl_mint(),
            amount: change(Asset::Spl),
            blinding: derive_blinding(&seed, 0),
            ..Default::default()
        });
    }
    if change(Asset::Sol) > 0 {
        expected.push(OutputUtxo {
            owner_hash,
            asset: SOL_MINT,
            amount: change(Asset::Sol),
            blinding: derive_blinding(&seed, 1),
            ..Default::default()
        });
    }
    for (i, (recipient, send)) in recipients.iter().zip(&plan.sends).enumerate() {
        expected.push(OutputUtxo {
            owner_hash: recipient.shielded_address().unwrap().owner_hash().unwrap(),
            asset: asset_addr(send.asset),
            amount: send.amount,
            blinding: derive_blinding(&seed, 2 + i as u8),
            ..Default::default()
        });
    }
    assert_eq!(outputs, expected.as_slice());

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
    assert_eq!(
        external_data,
        &ExternalData {
            instruction_discriminator: 0,
            expiry_unix_ts: 0,
            sender_view_tag: sender.get_sender_view_tag(0).unwrap(),
            relayer_fee: 0,
            public_sol_amount: net_public(Asset::Sol).unsigned_abs() as u64,
            public_spl_amount: net_public(Asset::Spl).unsigned_abs() as u64,
            user_sol_account,
            user_spl_token,
            spl_token_interface,
            encrypted_utxos: external_data.encrypted_utxos.clone(),
        }
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
            recipient_viewing_pks: recipients.iter().map(|r| r.viewing_pubkey()).collect(),
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

fn start_prover() {
    // Point the prover at the in-repo proving keys (once, to avoid a concurrent
    // set_var race across the non-serial scenarios).
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover().expect("start prover");
}

fn prove_and_verify_p256(result: &TransferP256ProofResult) {
    start_prover();
    let proof = ProverClient::local()
        .prove_transfer_p256(&result.inputs)
        .expect("prove transfer");
    let commitments = proof
        .commitment
        .expect("P256 transfer proof must carry a commitment");
    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof.a,
        &proof.b,
        &proof.c,
        &commitments.commitment,
        &commitments.commitment_pok,
        &public_inputs,
        &transfer_p256_2_3::VERIFYINGKEY,
    )
    .expect("construct verifier");
    verifier.verify().expect("groth16 proof verifies");
}

fn prove_and_verify_eddsa(result: &TransferProofResult) {
    start_prover();
    let proof = ProverClient::local()
        .prove_transfer(&result.inputs)
        .expect("prove transfer-eddsa");
    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        &transfer_2_3::VERIFYINGKEY,
    )
    .expect("construct verifier");
    verifier.verify().expect("groth16 proof verifies");
}
