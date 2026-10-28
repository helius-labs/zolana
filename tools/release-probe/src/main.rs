// Build as a temporary xtask binary inside the immutable protocol checkout.
// Inputs are the release's committed synthetic fixtures, never real witnesses.
use std::{fs, thread, time::Instant};

use anyhow::{anyhow, ensure, Context, Result};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use spr_client::prover::indexed::{IndexedTransferPreparation, IndexedTransferRail};
use spr_client::{
    error::ClientError,
    prover::{
        known_proving_keys, tee::TeePolicy, ExpectedProvingKey, Proof, ProveRequest, Prover,
        ProverClient,
    },
};
use spr_interface::verifying_keys::{transfer_confidential_2_2, transfer_eddsa_ring_2_2};
use spr_keypair::ShieldedKeypair;
use spr_transaction::{
    instructions::transact::ConfidentialTransaction,
    utxo::{SppProofInputUtxo, SppProofOutputUtxo},
    LocalShieldedKeys, Mint,
};
use zeroize::Zeroizing;

fn indexed_case(prover: &ProverClient) -> Result<()> {
    // A fresh zero-value address reservation needs a real non-inclusion proof,
    // but no deposit, existing wallet witness or on-chain transaction.
    let owner = ShieldedKeypair::new_ed25519()?;
    let sender = owner.shielded_address()?;
    let payer = sender.solana_address()?;
    let mut seed = [0; 32];
    seed[31] = 42;
    let address = SppProofInputUtxo::new_address(owner.signing_pubkey(), seed, 0)?;
    let keys = LocalShieldedKeys::from_keypair(&owner)?;
    let mut transaction =
        ConfidentialTransaction::new_with_addresses(Vec::new(), vec![address], payer)?;
    transaction.add_output_utxo(SppProofOutputUtxo::new(Mint::SOL, 0, sender)?)?;
    let transaction = transaction.finalize(&sender)?.encrypt_with_keys(&keys)?;
    let request = IndexedTransferPreparation {
        transaction,
        rail: IndexedTransferRail::Confidential,
    }
    .prepare(&owner)?;
    let started = Instant::now();
    let proven = prover
        .prove_indexed(&request)
        .context("encrypted indexed proof request")?;
    // The SDK checks the resolved transcript and verifies the Groth16 proof
    // against the release VK before returning ProvenIndexedTransfer.
    ensure!(matches!(
        proven.data.circuit,
        spr_interface::instruction::instruction_data::transact::CircuitId::ConfidentialEddsa(
            1,
            2,
            _
        )
    ));
    ensure!(proven.input_tree_ids == vec![0]);
    println!(
        "{}",
        serde_json::json!({"event":"indexed_proof_verified", "key":"transfer_confidential_1_2.key", "seconds":started.elapsed().as_secs_f64(), "tree_ids":proven.input_tree_ids, "public_input_hash":hex::encode(proven.public_input_hash), "transaction_submitted":false})
    );
    Ok(())
}

struct Request {
    body: String,
    key: ExpectedProvingKey,
}

impl ProveRequest for Request {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(Zeroizing::new(self.body.clone()))
    }
    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.key.clone())
    }
}

fn verify(proof: &Proof, hash: [u8; 32], vk: &Groth16Verifyingkey) -> Result<()> {
    let inputs = [hash];
    let mut verifier = match &proof.commitment {
        Some(commitment) => Groth16Verifier::new_with_commitment(
            &proof.a,
            &proof.b,
            &proof.c,
            &commitment.commitment,
            &commitment.commitment_pok,
            &inputs,
            vk,
        ),
        None => Groth16Verifier::new(&proof.a, &proof.b, &proof.c, &inputs, vk),
    }
    .map_err(|e| anyhow!("verifier construction: {e:?}"))?;
    verifier
        .verify()
        .map_err(|e| anyhow!("proof verification: {e:?}"))
}

fn case(prover: &ProverClient, path: &str, key: &str, vk: &Groth16Verifyingkey) -> Result<()> {
    let body = fs::read_to_string(path)?;
    let mut json: serde_json::Value = serde_json::from_str(&body)?;
    let raw = hex::decode(
        json["publicInputHash"]
            .as_str()
            .context("public hash")?
            .trim_start_matches("0x"),
    )?;
    let hash: [u8; 32] = raw.try_into().map_err(|_| anyhow!("public hash length"))?;
    let sha256 = known_proving_keys()
        .find(|(name, _)| *name == key)
        .context("known key")?
        .1;
    let request = Request {
        body,
        key: ExpectedProvingKey {
            name: key.to_owned(),
            sha256,
        },
    };
    let started = Instant::now();
    let proof = prover.prove(&request).context("encrypted proof request")?;
    verify(&proof, hash, vk)?;
    let mut wrong = hash;
    wrong[31] ^= 1;
    ensure!(
        verify(&proof, wrong, vk).is_err(),
        "proof accepted a changed public input"
    );
    println!(
        "{}",
        serde_json::json!({"event":"cold_proof_verified", "key":key, "seconds":started.elapsed().as_secs_f64(), "wrong_public_rejected":true})
    );

    if std::env::var_os("RELEASE_BENCHMARK").is_none() {
        return Ok(());
    }

    let started = Instant::now();
    thread::scope(|scope| -> Result<()> {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let request = &request;
                scope.spawn(move || -> Result<()> {
                    let proof = prover.prove(request)?;
                    verify(&proof, hash, vk)
                })
            })
            .collect();
        for handle in handles {
            handle
                .join()
                .map_err(|_| anyhow!("request thread panicked"))??;
        }
        Ok(())
    })?;
    println!(
        "{}",
        serde_json::json!({"event":"parallel_proofs_verified", "key":key, "requests":8, "seconds":started.elapsed().as_secs_f64()})
    );

    json["publicInputHash"] = format!("0x{}", hex::encode(wrong)).into();
    let invalid = Request {
        body: serde_json::to_string(&json)?,
        key: request.key,
    };
    ensure!(
        prover.prove(&invalid).is_err(),
        "prover accepted an inconsistent witness"
    );
    println!(
        "{}",
        serde_json::json!({"event":"invalid_witness_rejected", "key":key})
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 5,
        "usage: client-check URL POLICY CONFIDENTIAL_FIXTURE EDDSA_FIXTURE"
    );
    let expected_tree = std::env::var("EXPECTED_TREE")
        .context("EXPECTED_TREE must identify the selected release's protocol tree")?;
    ensure!(
        spr_interface::pda::tree(0).to_string() == expected_tree,
        "SDK tree differs from the selected release"
    );
    let prover = ProverClient::new(args[1].clone())
        .with_tee(TeePolicy::from_file_json(&fs::read_to_string(&args[2])?)?);
    let attested = prover.attest().context("live Nitro attestation")?;
    println!("attested {attested}");
    println!(
        "{}",
        serde_json::json!({"event":"attested_identity","hpke_public_key":hex::encode(attested.hpke_public_key)})
    );
    let report = prover
        .check_proving_keys()
        .context("encrypted key digest check")?;
    println!(
        "{}",
        serde_json::json!({"event":"encrypted_key_check", "keys":report.keys.len()})
    );
    case(
        &prover,
        &args[3],
        "transfer_confidential_2_2.key",
        &transfer_confidential_2_2::VERIFYINGKEY,
    )?;
    case(
        &prover,
        &args[4],
        "transfer_eddsa_ring_2_2.key",
        &transfer_eddsa_ring_2_2::VERIFYINGKEY,
    )?;
    indexed_case(&prover)?;
    Ok(())
}
