//! End-to-end zone fold test: three UTXOs spent together as two `(2,2)` legs of
//! one account, folded into one proof.
//!
//! The fold is verified on the host against the committed fold verifying key
//! using the public-input hash the on-chain `ZoneFoldProof` recomputes, so this
//! covers the circuit, the prover glue, the SDK, and the on-chain composition.

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
};
use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use zolana_client::prover::{spawn_prover, SERVER_ADDRESS};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::verifying_keys::zone_fold_2_2_l2;

use crate::prover::{
    error::SquadsProverError,
    zone::{derive_change_blinding, ZoneProofInputs, ZoneProposal, ZoneRecipient, ZoneUtxo},
    zone_fold::prove_zone_fold,
};

fn prover_url() -> String {
    std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| SERVER_ADDRESS.to_string())
}

fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover().expect("prover server must be available");
}

fn random_field() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0;
    b
}

fn nullifier_pubkey(nullifier_secret: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[nullifier_secret.as_slice()]).expect("poseidon")
}

fn utxo(amount: u64, owner_key_hash: [u8; 32], nullifier_pk: [u8; 32], is_dummy: bool) -> ZoneUtxo {
    ZoneUtxo {
        owner_key_hash,
        nullifier_pubkey: nullifier_pk,
        asset: [0u8; 32],
        amount,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy,
    }
}

fn verify_on_host(proof: &[u8; 192], public_input: &[u8; 32]) -> bool {
    let vk = &zone_fold_2_2_l2::VERIFYINGKEY;
    assert!(
        vk.vk_commitment.is_some(),
        "the fold must be the BSB22 rail",
    );
    let proof_a = decompress_g1(&to32(&proof[0..32])).expect("decompress a");
    let proof_b = decompress_g2(&to64(&proof[32..96])).expect("decompress b");
    let proof_c = decompress_g1(&to32(&proof[96..128])).expect("decompress c");
    let commitment = decompress_g1(&to32(&proof[128..160])).expect("decompress commitment");
    let commitment_pok = decompress_g1(&to32(&proof[160..192])).expect("decompress pok");

    let public_inputs = [*public_input];
    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof_a,
        &proof_b,
        &proof_c,
        &commitment,
        &commitment_pok,
        &public_inputs,
        vk,
    )
    .expect("verifier construction");
    verifier.verify().is_ok()
}

fn to32(s: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(s);
    o
}

fn to64(s: &[u8]) -> [u8; 64] {
    let mut o = [0u8; 64];
    o.copy_from_slice(s);
    o
}

/// One sender and one recipient, reused across every leg a test builds.
struct Parties {
    sender_viewing: SecretKey,
    sender_nullifier_secret: [u8; 32],
    sender_nullifier_pk: [u8; 32],
    sender_owner: [u8; 32],
    recipient: ZoneRecipient,
}

impl Parties {
    fn random() -> Self {
        let sender_nullifier_secret = random_field();
        Self {
            sender_viewing: SecretKey::random(&mut OsRng),
            sender_nullifier_secret,
            sender_nullifier_pk: nullifier_pubkey(&sender_nullifier_secret),
            sender_owner: random_field(),
            recipient: ZoneRecipient {
                owner_key_hash: random_field(),
                nullifier_pubkey: random_field(),
                viewing_pubkey: P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key()),
            },
        }
    }

    /// A `(2,2)` leg spending `amounts` and paying `transferred` to the
    /// recipient. A `None` second amount is a dummy input slot, which is how a
    /// run spends an odd number of UTXOs.
    fn leg(&self, amounts: (u64, Option<u64>), transferred: u64) -> ZoneProofInputs {
        let second = amounts.1.unwrap_or(0);
        let inputs = vec![
            utxo(
                amounts.0,
                self.sender_owner,
                self.sender_nullifier_pk,
                false,
            ),
            utxo(
                second,
                self.sender_owner,
                self.sender_nullifier_pk,
                amounts.1.is_none(),
            ),
        ];
        let change_blinding = derive_change_blinding(
            &self.sender_viewing,
            &self.sender_nullifier_secret,
            &inputs[0],
        )
        .expect("derive change blinding");
        let change = ZoneUtxo {
            owner_key_hash: self.sender_owner,
            nullifier_pubkey: self.sender_nullifier_pk,
            asset: [0u8; 32],
            amount: amounts.0 + second - transferred,
            blinding: change_blinding,
            program_data_hash: [0u8; 32],
            ring_data_hash: [0u8; 32],
            ring_program_id: [0u8; 32],
            is_dummy: false,
        };
        let recipient_output = ZoneUtxo {
            owner_key_hash: self.recipient.owner_key_hash,
            nullifier_pubkey: self.recipient.nullifier_pubkey,
            asset: [0u8; 32],
            amount: transferred,
            blinding: random_field(),
            program_data_hash: [0u8; 32],
            ring_data_hash: [0u8; 32],
            ring_program_id: [0u8; 32],
            is_dummy: false,
        };
        ZoneProofInputs {
            viewing_secret_key: self.sender_viewing.clone(),
            nullifier_secret: self.sender_nullifier_secret,
            inputs,
            outputs: vec![change, recipient_output],
            external_data_hash: random_field(),
            recipient: Some(self.recipient.clone()),
            proposal: None,
            public_amount: [0u8; 32],
        }
    }
}

#[test]
fn three_utxos_spend_together_under_one_fold() {
    start_prover();

    let parties = Parties::random();
    let legs = vec![
        parties.leg((700, Some(300)), 400),
        parties.leg((500, None), 200),
    ];

    let folded = prove_zone_fold(legs, &prover_url()).expect("fold proof generation must succeed");

    assert_eq!(folded.legs.len(), 2);
    for leg in &folded.legs {
        assert_eq!(leg.sender_ciphertext.len(), 40);
        assert_eq!(leg.recipient_ciphertext.len(), 71);
        assert!(leg.tx_viewing_pk.is_some());
        // A folded leg carries no proposal, so its proposal hash is zero.
        assert_eq!(leg.proposal_hash, [0u8; 32]);
    }
    // Each leg keeps its own transaction, so the two are distinct spends.
    assert_ne!(
        folded.legs[0].private_tx_hash,
        folded.legs[1].private_tx_hash
    );

    assert!(
        verify_on_host(&folded.proof, &folded.public_input_hash),
        "host Groth16 verification of the folded zone proof failed",
    );

    let mut tampered = folded.public_input_hash;
    tampered[1] ^= 1;
    assert!(
        !verify_on_host(&folded.proof, &tampered),
        "verification must fail for a tampered public input",
    );
}

/// The SDK rejects a proposal on any leg before any prover request.
#[test]
fn a_leg_carrying_a_proposal_is_rejected() {
    let parties = Parties::random();
    let mut legs = vec![
        parties.leg((700, Some(300)), 400),
        parties.leg((500, None), 200),
    ];
    legs[1].proposal = Some(ZoneProposal {
        amount: [0u8; 32],
        recipient: [0u8; 32],
        asset: [0u8; 32],
        destination: [0u8; 32],
        blinding: random_field(),
        public_amount: [0u8; 32],
    });

    assert!(matches!(
        prove_zone_fold(legs, &prover_url()),
        Err(SquadsProverError::FoldedProposal)
    ));
}

/// A leg count with no key is rejected before any proving work.
#[test]
fn an_unsupported_leg_count_is_rejected() {
    let parties = Parties::random();
    assert!(matches!(
        prove_zone_fold(vec![parties.leg((700, Some(300)), 400)], &prover_url()),
        Err(SquadsProverError::UnsupportedLegCount(1))
    ));
}
