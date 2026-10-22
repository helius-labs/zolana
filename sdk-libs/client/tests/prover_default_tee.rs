//! The default deployment must accept its measured AWS-signed evidence without
//! a caller-supplied policy. The live test also exercises encrypted proving.

use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;
use zolana_client::{
    prover::{
        indexed::ProofDataSource,
        known_proving_keys,
        tee::{
            verify, Attestation, Platform, PlatformPolicy, TeeError, TeePolicy, DEFAULT_PROVER_URL,
        },
        verify_proof_statement, Delivery, ExpectedProvingKey, ProveRequest, ProverClient,
    },
    ClientError, Prover,
};
use zolana_interface::{verifying_keys::CircuitId, N_PUBLIC_SLOTS};

const RECORDED_ATTESTATION: &str =
    include_str!("../../../prover/tee/testdata/devnet_d_tee_2_attestation.json");
const TRANSFER: &str =
    include_str!("../../../prover/server/prover/request/testdata/transfer-2x2.json");
const TRANSFER_KEY: &str = "transfer_confidential_2_2.key";

#[derive(Deserialize)]
struct RecordedAttestation {
    captured_at: u64,
    nonce: String,
    attestation: Attestation,
}

#[test]
fn the_release_policy_accepts_the_measured_devnet_d_tee_2_attestation() {
    let fixture: RecordedAttestation = serde_json::from_str(RECORDED_ATTESTATION).unwrap();
    let nonce: [u8; 32] = hex::decode(fixture.nonce).unwrap().try_into().unwrap();
    let policy = TeePolicy::default_deployment().unwrap();
    let attested = verify(fixture.attestation, &policy, &nonce, fixture.captured_at)
        .expect("the release pin must accept the AWS-signed measured deployment");
    assert_eq!(attested.platform, Platform::AwsNitro);
}

#[test]
fn an_archived_quote_cannot_be_replayed_for_a_new_session_nonce() {
    let fixture: RecordedAttestation = serde_json::from_str(RECORDED_ATTESTATION).unwrap();
    let mut nonce: [u8; 32] = hex::decode(fixture.nonce).unwrap().try_into().unwrap();
    nonce[0] ^= 1;
    assert!(matches!(
        verify(
            fixture.attestation,
            &TeePolicy::default_deployment().unwrap(),
            &nonce,
            fixture.captured_at
        ),
        Err(TeeError::NitroDocument(_))
    ));
}

#[test]
fn the_new_deployment_refuses_the_retired_hpke_key_pin() {
    let fixture: RecordedAttestation = serde_json::from_str(RECORDED_ATTESTATION).unwrap();
    let nonce: [u8; 32] = hex::decode(fixture.nonce).unwrap().try_into().unwrap();
    let PlatformPolicy::AwsNitro(mut pins) =
        TeePolicy::default_deployment().unwrap().pins().clone()
    else {
        panic!("the default deployment must remain Nitro");
    };
    pins.hpke_public_key = Some(
        hex::decode("f88ce265f3a519822d1fb7b1927d00e3d92c9dd3dc151cf9eebcb8fedd995f1a")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert!(matches!(
        verify(
            fixture.attestation,
            &TeePolicy::new(PlatformPolicy::AwsNitro(pins)),
            &nonce,
            fixture.captured_at
        ),
        Err(TeeError::HpkeKeyMismatch)
    ));
}

#[test]
fn the_default_endpoint_requires_attestation_and_prover_proof_data() {
    assert_eq!(DEFAULT_PROVER_URL, "https://d1unet9hn0mci0.cloudfront.net");
    let prover = ProverClient::new(DEFAULT_PROVER_URL.into());
    assert_eq!(
        (prover.has_tee(), prover.proof_data_source()),
        (true, ProofDataSource::Prover)
    );
}

struct TransferFixture;

impl ProveRequest for TransferFixture {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(Zeroizing::new(TRANSFER.to_owned()))
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        let (name, sha256) = known_proving_keys()
            .find(|(name, _)| *name == TRANSFER_KEY)
            .ok_or_else(|| ClientError::Prover("the fixture's proving key is not pinned".into()))?;
        Ok(ExpectedProvingKey {
            name: name.into(),
            sha256,
        })
    }

    fn delivery(&self) -> Delivery {
        Delivery::InResponse
    }
}

/// No chain access or wallet data: this asks the release-pinned enclave to prove
/// the committed synthetic witness and checks the proof against the on-chain VK.
#[test]
#[ignore = "contacts the default devnet TEE and generates one synthetic transfer proof"]
fn the_default_deployment_attests_and_verifies_an_encrypted_fixture_proof() {
    let prover =
        ProverClient::new(DEFAULT_PROVER_URL.into()).with_proof_timeout(Duration::from_secs(180));
    assert!(prover.has_tee());
    let attested = prover
        .attest()
        .expect("attest using the bundled release policy");
    println!("attested default deployment: {attested}");

    let proof = prover
        .prove(&TransferFixture)
        .expect("encrypted proof request using the attested session");
    let fixture: serde_json::Value = serde_json::from_str(TRANSFER).unwrap();
    let public_input_hash: [u8; 32] = hex::decode(
        fixture["publicInputHash"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let verifying_key = CircuitId::ConfidentialEddsa(2, 2, N_PUBLIC_SLOTS as u8)
        .verifying_key()
        .unwrap();
    verify_proof_statement(&proof, public_input_hash, verifying_key)
        .expect("the enclave's proof must verify against the committed on-chain key");
    println!("encrypted transfer proof verified against the committed 2x2 verifying key");
}
