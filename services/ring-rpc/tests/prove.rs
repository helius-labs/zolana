//! Needs the gnark keys, see `just ensure-custom-ring-keys`.

use custom_ring_prover::GO_CIRCUITS_LINKED;
use zeroize::Zeroizing;
use zolana_keypair::ViewingKey;
use zolana_ring_client::AuditorEncryption;
use zolana_ring_rpc::prove::{prove_auditor_key_encryption, AuditWitness};

#[test]
fn proves_the_encryption_the_witness_describes() {
    if !GO_CIRCUITS_LINKED {
        eprintln!("skipping, Go circuits not linked");
        return;
    }
    let auditor = ViewingKey::new();
    let tx_viewing = ViewingKey::new();
    let tx_viewing_sk = tx_viewing.secret_bytes();
    let AuditorEncryption {
        ephemeral_sk,
        message: _,
    } = AuditorEncryption::new(&tx_viewing_sk, &auditor.pubkey()).expect("encrypt");

    let proof = prove_auditor_key_encryption(
        &AuditWitness {
            private_tx_hash: [7u8; 32],
            tx_viewing_sk: Zeroizing::new(*tx_viewing_sk),
            eph_sk: ephemeral_sk,
        },
        &auditor.pubkey(),
    )
    .expect("prove");
    assert_eq!(wincode::serialize(&proof).expect("serialize").len(), 192);
}
