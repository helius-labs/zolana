//! Shared helpers for the transfer (2,3) integration tests: build real witnesses
//! (state inclusion + nullifier non-inclusion proofs via the reference trees),
//! a recipient-and-change transfer builder, and prove+verify against the
//! committed `transfer_2_3` verifying key.

use groth16_solana::groth16::Groth16Verifier;
use light_hasher::{Hasher, Poseidon};
use light_merkle_tree_reference::MerkleTree;
use num_bigint::BigUint;
use p256::ecdsa::SigningKey;
use rand::{rngs::ThreadRng, RngCore};
use zolana_client::field::BN254_MODULUS_DEC;
use zolana_client::transfer::input_utxo_hash;
use zolana_client::{
    spawn_prover, NullifierNonInclusionProof, P256Owner, ProverClient, PublicAmounts,
    StateInclusionProof, TransferNewOutput, TransferProofResult, TransferProver,
    TransferSpendInput, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::verifying_keys::transfer_2_3::VERIFYINGKEY;
use zolana_keypair::hash::owner_hash;
use zolana_keypair::{NullifierKey, PublicKey};
use zolana_transaction::{Data, ExternalData, Utxo, SOL_MINT};

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

/// A random value guaranteed to be a valid BN254 field element (poseidon inputs
/// must be < ~254 bits): zero the most-significant byte.
fn random_field(rng: &mut ThreadRng) -> [u8; 32] {
    let mut b = random_32(rng);
    b[0] = 0;
    b
}

/// A transfer recipient: a Solana (ed25519) owner plus its nullifier pubkey,
/// enough to mint an output UTXO to them.
pub struct Recipient {
    owner: PublicKey,
    nullifier_pk: [u8; 32],
}

impl Recipient {
    pub fn random(rng: &mut ThreadRng) -> Self {
        let owner = PublicKey::from_ed25519(&random_32(rng));
        let nullifier_pk = NullifierKey::from_secret(random_blinding(rng))
            .pubkey()
            .expect("nullifier pubkey");
        Self {
            owner,
            nullifier_pk,
        }
    }

    fn output(&self, amount: u64, rng: &mut ThreadRng) -> TransferNewOutput {
        TransferNewOutput {
            owner_hash: owner_hash(&self.owner, &self.nullifier_pk).expect("owner hash"),
            asset: SOL_MINT,
            amount,
            blinding: random_blinding(rng),
        }
    }
}

/// Build the state-inclusion proofs for a set of input UTXO leaf hashes inserted
/// into a fresh height-26 Poseidon merkle tree (one shared root).
fn state_proofs(leaves: &[[u8; 32]]) -> Vec<StateInclusionProof> {
    let mut tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    for leaf in leaves {
        tree.append(leaf).expect("append state leaf");
    }
    let root = tree.root();
    (0..leaves.len())
        .map(|i| StateInclusionProof {
            path_elements: tree
                .get_proof_of_leaf(i, true)
                .expect("state proof")
                .try_into()
                .expect("state path length"),
            leaf_index: i as u64,
            root,
        })
        .collect()
}

/// p - 1 (BN254 scalar field modulus minus one), big-endian. The SPP nullifier
/// tree's indexed-value domain spans the whole field, so the empty-tree sentinel
/// low element is (value 0, next_value p-1) (see the circuit's full_field_compare:
/// "init sentinel p-1"). p itself can't be used: a field witness assigned p
/// reduces to 0.
fn nullifier_upper_bound() -> [u8; 32] {
    let upper = BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("modulus") - 1u32;
    let bytes = upper.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Build nullifier non-inclusion proofs against a fresh (empty) height-40 indexed
/// tree whose single sentinel leaf is `Poseidon(0, p-1)`: every nullifier is
/// bracketed by `0 < nullifier < p-1`.
fn nullifier_proofs(count: usize) -> Vec<NullifierNonInclusionProof> {
    let low_value = [0u8; 32];
    let next_value = nullifier_upper_bound();
    let sentinel_leaf = Poseidon::hashv(&[&low_value, &next_value]).expect("sentinel leaf");

    let mut tree = MerkleTree::<Poseidon>::new(NULLIFIER_TREE_HEIGHT, 0);
    tree.append(&sentinel_leaf).expect("append sentinel");
    let root = tree.root();
    let low_path_elements: [[u8; 32]; NULLIFIER_TREE_HEIGHT] = tree
        .get_proof_of_leaf(0, true)
        .expect("sentinel proof")
        .try_into()
        .expect("nullifier path length");

    (0..count)
        .map(|_| NullifierNonInclusionProof {
            low_value,
            next_value,
            low_path_elements,
            low_leaf_index: 0,
            root,
        })
        .collect()
}

/// Build real spend inputs (random owner / nullifier key / blinding per input)
/// with consistent state + nullifier proofs.
fn build_inputs(amounts: &[u64], rng: &mut ThreadRng) -> Vec<TransferSpendInput> {
    let utxos: Vec<(Utxo, NullifierKey)> = amounts
        .iter()
        .map(|&amount| {
            let owner = PublicKey::from_ed25519(&random_32(rng));
            let nullifier_key = NullifierKey::from_secret(random_blinding(rng));
            let utxo = Utxo {
                owner,
                asset: SOL_MINT,
                amount,
                blinding: random_blinding(rng),
                zone_program_id: None,
                data: Data::default(),
            };
            (utxo, nullifier_key)
        })
        .collect();

    let utxo_hashes: Vec<[u8; 32]> = utxos
        .iter()
        .map(|(utxo, nk)| input_utxo_hash(utxo, nk).expect("utxo hash"))
        .collect();

    let states = state_proofs(&utxo_hashes);
    let nfs = nullifier_proofs(utxos.len());

    utxos
        .into_iter()
        .zip(states)
        .zip(nfs)
        .map(
            |(((utxo, nullifier_key), state_proof), nullifier_proof)| TransferSpendInput {
                utxo,
                nullifier_key,
                state_proof,
                nullifier_proof,
            },
        )
        .collect()
}

fn public_amounts_sol(public_sol: u64) -> PublicAmounts {
    let mut sol = [0u8; 32];
    sol[24..].copy_from_slice(&public_sol.to_be_bytes());
    PublicAmounts {
        sol,
        spl: [0u8; 32],
        asset: [0u8; 32],
    }
}

/// Build and prove a P256-rail transfer: spend `input_amounts` plus an optional
/// `public_sol` deposit, send each amount in `send_amounts` to a fresh recipient,
/// and return the remainder to the sender as a change output. The proof is
/// verified against `transfer_2_3::VERIFYINGKEY`.
pub fn run_transfer(input_amounts: &[u64], public_sol: u64, send_amounts: &[u64]) {
    let mut rng = rand::thread_rng();

    let inputs = build_inputs(input_amounts, &mut rng);

    let total_in: u64 = input_amounts.iter().sum::<u64>() + public_sol;
    let total_sent: u64 = send_amounts.iter().sum();
    assert!(total_sent <= total_in, "sends exceed available value");
    let change = total_in - total_sent;

    let mut outputs: Vec<TransferNewOutput> = send_amounts
        .iter()
        .map(|&amount| Recipient::random(&mut rng).output(amount, &mut rng))
        .collect();
    if change > 0 {
        outputs.push(Recipient::random(&mut rng).output(change, &mut rng));
    }

    // P256 signature is unused for Solana-owned/dummy inputs; a fixed key suffices.
    let signing_key = SigningKey::from_slice(&[1u8; 32]).expect("p256 signing key");
    let result = TransferProver {
        inputs,
        outputs,
        external_data: ExternalData::default(),
        public_amounts: public_amounts_sol(public_sol),
        payer_pubkey_hash: random_field(&mut rng),
        p256_owner: P256Owner::Signer(signing_key),
    }
    .build()
    .expect("build transfer witness");

    prove_and_verify(&result);
}

fn prove_and_verify(result: &TransferProofResult) {
    // Point the prover at the in-repo proving keys (once, to avoid a concurrent
    // set_var race across the non-serial tests).
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "LIGHT_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        );
    });

    spawn_prover().expect("start prover");

    let proof = ProverClient::local()
        .prove_transfer(&result.inputs)
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
        &VERIFYINGKEY,
    )
    .expect("construct verifier");
    verifier.verify().expect("groth16 proof verifies");
}
