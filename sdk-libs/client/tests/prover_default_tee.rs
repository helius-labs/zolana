//! Archived caller-supplied pins must accept their measured AWS-signed evidence.
//! Opt-in live tests exercise encrypted proving with an explicit URL and policy.

use std::time::Duration;

use serde::Deserialize;
use spr_client::{
    prover::{
        indexed::ProofDataSource,
        known_proving_keys,
        tee::{verify, Attestation, Platform, PlatformPolicy, TeeError, TeePolicy},
        verify_proof_statement, Delivery, ExpectedProvingKey, ProveRequest, ProverClient,
    },
    ClientError, Prover,
};
use spr_interface::{verifying_keys::CircuitId, N_PUBLIC_SLOTS};
use zeroize::Zeroizing;

const RECORDED_ATTESTATION: &str =
    include_str!("../../../prover/tee/testdata/devnet_e_tee_1_attestation.json");
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
fn the_release_policy_accepts_the_measured_devnet_e_tee_1_attestation() {
    let fixture: RecordedAttestation = serde_json::from_str(RECORDED_ATTESTATION).unwrap();
    let nonce: [u8; 32] = hex::decode(fixture.nonce).unwrap().try_into().unwrap();
    let policy = TeePolicy::from_file_json(include_str!(
        "../../../prover/tee/deployments/devnet-e-v0.6.0-alpha.json"
    ))
    .unwrap();
    let attested = verify(fixture.attestation, &policy, &nonce, fixture.captured_at)
        .expect("the release pin must accept the AWS-signed measured deployment");
    assert_eq!(attested.platform, Platform::AwsNitro);
}

#[test]
fn the_release_policy_refuses_the_retired_devnet_d_deployment() {
    let fixture: RecordedAttestation = serde_json::from_str(include_str!(
        "../../../prover/tee/testdata/devnet_d_tee_3_attestation.json"
    ))
    .unwrap();
    let nonce: [u8; 32] = hex::decode(fixture.nonce).unwrap().try_into().unwrap();
    assert!(matches!(
        verify(
            fixture.attestation,
            &TeePolicy::from_file_json(include_str!(
                "../../../prover/tee/deployments/devnet-e-v0.6.0-alpha.json"
            ))
            .unwrap(),
            &nonce,
            fixture.captured_at
        ),
        Err(TeeError::EnclaveMeasurementNotAllowed)
    ));
}

#[test]
fn an_archived_quote_cannot_be_replayed_for_a_new_session_nonce() {
    let fixture: RecordedAttestation = serde_json::from_str(RECORDED_ATTESTATION).unwrap();
    let mut nonce: [u8; 32] = hex::decode(fixture.nonce).unwrap().try_into().unwrap();
    nonce[0] ^= 1;
    assert!(matches!(
        verify(
            fixture.attestation,
            &TeePolicy::from_file_json(include_str!(
                "../../../prover/tee/deployments/devnet-e-v0.6.0-alpha.json"
            ))
            .unwrap(),
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
    let PlatformPolicy::AwsNitro(mut pins) = TeePolicy::from_file_json(include_str!(
        "../../../prover/tee/deployments/devnet-e-v0.6.0-alpha.json"
    ))
    .unwrap()
    .pins()
    .clone() else {
        panic!("the default deployment must remain Nitro");
    };
    pins.hpke_public_key = Some(
        hex::decode("270e90208e7f79a8fe1ca1b2eb6670421a3ae95b4119928a915cbd8977c2e055")
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
    let prover = ProverClient::new("https://prover.example".into()).with_tee(
        TeePolicy::from_file_json(include_str!(
            "../../../prover/tee/deployments/devnet-e-v0.6.0-alpha.json"
        ))
        .unwrap(),
    );
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
    assert_encrypted_fixture_proof(
        "ZOLANA_DEVNET_PROVER_URL",
        "ZOLANA_DEVNET_PROVER_TEE_POLICY",
    );
}

#[test]
#[ignore = "contacts the mainnet TEE and generates one synthetic transfer proof"]
fn the_mainnet_deployment_attests_and_verifies_an_encrypted_fixture_proof() {
    assert_encrypted_fixture_proof(
        "ZOLANA_MAINNET_PROVER_URL",
        "ZOLANA_MAINNET_PROVER_TEE_POLICY",
    );
}

fn assert_encrypted_fixture_proof(url_env: &str, policy_env: &str) {
    let url = std::env::var(url_env).expect("supply the live prover URL");
    let policy_path = std::env::var(policy_env).expect("supply the reviewed policy file");
    let policy = TeePolicy::from_file_json(&std::fs::read_to_string(policy_path).unwrap()).unwrap();
    let prover = ProverClient::new(url)
        .with_tee(policy)
        .with_proof_timeout(Duration::from_secs(180));
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
    let verifying_key = CircuitId::ConfidentialSigner(2, 2, N_PUBLIC_SLOTS as u8)
        .verifying_key()
        .unwrap();
    verify_proof_statement(&proof, public_input_hash, verifying_key)
        .expect("the enclave's proof must verify against the committed on-chain key");
    println!("encrypted transfer proof verified against the committed 2x2 verifying key");
}
