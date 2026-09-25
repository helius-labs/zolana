//! Rewrites the audited deposits the custom-ring program tests verify,
//! `custom-rings/program/tests/fixtures/deposit-audit/{2,8}.bin`. Run it with
//! `just dump-deposit-audit-fixtures` whenever the SPP ring deposit layout or
//! the deposit proving key changes.

#[path = "../../../sdk-libs/client/tests/prover_bootstrap.rs"]
mod prover_bootstrap;

use custom_ring_interface::{
    tag, CustomRingProof, DepositContext, DepositPublicInput, RingDepositAuditCapsule,
    MAX_RING_DEPOSIT_AUDIT_SLOTS,
};
use custom_ring_sdk::{
    to_instruction_proof, CustomRing, Deposit, DepositAsset, EscrowBinding, RingDepositProofRequest,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::ProverClient;
use zolana_keypair::{random_blinding, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_program::instruction::{RingAssetDeposit, RingDeposit};
use zolana_ring_client::{DepositOpening, DepositSeal};
use zolana_transaction::{owner_utxo_hash, RingDepositPlaintext};

// `proven_fixture` in the program's deposit audit tests pins these accounts
// and the auditor public key of `AUDITOR_SECRET`.
const RING: [u8; 32] = [77; 32];
const TREE: [u8; 32] = [51; 32];
const DEPOSITOR: [u8; 32] = [44; 32];
const AUDITOR_SECRET: [u8; 32] = [0x11; 32];
const AMOUNT: u64 = 5;

/// The fixtures predate the key registry root index byte, the program tests
/// insert it at this offset.
const REGISTRY_INDEX: usize = 1 + CustomRingProof::SIZE;

#[test]
#[ignore = "rewrites the program's deposit audit fixtures, run with just dump-deposit-audit-fixtures"]
fn dump_deposit_audit_fixtures() {
    prover_bootstrap::start_prover();
    let prover = ProverClient::local();
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../program/tests/fixtures/deposit-audit"
    );
    for count in [2, 8] {
        let data = audited_deposit(&prover, count);
        std::fs::write(format!("{dir}/{count}.bin"), &data).expect("write fixture");
        eprintln!("wrote {dir}/{count}.bin ({} bytes)", data.len());
    }
}

fn audited_deposit(prover: &ProverClient, count: usize) -> Vec<u8> {
    let ring = CustomRing::new(Address::new_from_array(RING));
    let tree = Address::new_from_array(TREE);
    let depositor = Address::new_from_array(DEPOSITOR);
    let auditor = ViewingKey::from_bytes(&AUDITOR_SECRET)
        .expect("auditor key")
        .pubkey();
    // 1. Deposit to one recipient per slot, each output keeps its recipient
    // ciphertext behind the auditor capsule.
    let mut owner_pk_hashes = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    let mut nullifier_pks = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    let mut blindings = Zeroizing::new([[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]);
    let mut openings = Vec::with_capacity(count);
    let mut deposits = Vec::with_capacity(count);
    for (seed, ((owner_pk_hash, nullifier_pk), slot_blinding)) in (1..=count as u8).zip(
        owner_pk_hashes
            .iter_mut()
            .zip(nullifier_pks.iter_mut())
            .zip(blindings.iter_mut()),
    ) {
        let recipient = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
            .expect("recipient keypair");
        let address = recipient.shielded_address().expect("recipient address");
        let owner_hash = recipient.owner_hash().expect("owner hash");
        let blinding = random_blinding();
        *owner_pk_hash = address
            .signing_pubkey
            .owner_proof_input_hash()
            .expect("owner key hash");
        *nullifier_pk = address.nullifier_pubkey;
        *slot_blinding = blinding;
        openings.push(DepositOpening {
            owner_hash,
            blinding: Zeroizing::new(blinding),
        });
        deposits.push(RingAssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: recipient.recipient_bootstrap_view_tag(),
            owner_utxo_hash: owner_utxo_hash(&owner_hash, &blinding).expect("owner commitment"),
            amount: AMOUNT,
            ring_data_hash: [0; 32],
            encrypted: RingDepositPlaintext {
                blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&recipient.viewing_pubkey())
            .expect("recipient ciphertext"),
        });
    }
    let encryption = DepositSeal {
        openings: &openings,
        auditor_pk: &auditor,
    }
    .seal()
    .expect("seal openings");
    for ((slot, deposit), ciphertext) in (0u8..).zip(&mut deposits).zip(&encryption.ciphertexts) {
        deposit.encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: slot,
            eph_pk: encryption.ephemeral_pk.as_bytes(),
            ciphertext,
            recipient_ciphertext: &deposit.encrypted.ciphertext,
        }
        .encode();
    }
    // 2. Bind the proof to the ring, the tree and the exact SPP bytes the ring
    // forwards.
    let spp = RingDeposit {
        tree,
        depositor,
        ring_program_id: ring.program_id(),
        deposits: deposits.clone(),
    }
    .instruction()
    .expect("spp ring deposit");
    let context_hash = DepositContext {
        program_id: &RING,
        tree: &TREE,
        spp_data: &spp.data,
    }
    .hash()
    .expect("context hash");
    let owners: Vec<_> = deposits
        .iter()
        .map(|deposit| deposit.owner_utxo_hash)
        .collect();
    let public_input_hash = DepositPublicInput {
        context_hash: &context_hash,
        owner_utxo_hashes: &owners,
        ciphertexts: &encryption.ciphertexts,
        auditor_pk: auditor.as_bytes(),
        eph_pk: encryption.ephemeral_pk.as_bytes(),
        key_registry_root: None,
    }
    .hash()
    .expect("public input hash");
    let mut auditor_uncompressed = [0; 65];
    auditor_uncompressed.copy_from_slice(
        auditor
            .to_p256()
            .expect("auditor point")
            .to_encoded_point(false)
            .as_bytes(),
    );
    let proof = prover
        .prove(&RingDepositProofRequest {
            public_input_hash: &public_input_hash,
            context_hash: &context_hash,
            count: count as u8,
            owner_pk_hashes: &owner_pk_hashes,
            nullifier_pks: &nullifier_pks,
            blindings: &blindings,
            keys: &[None; MAX_RING_DEPOSIT_AUDIT_SLOTS],
            key_registry_root: None,
            ephemeral_sk: &encryption.ephemeral_sk,
            auditor_pk: &auditor_uncompressed,
        })
        .expect("deposit proof");
    // 3. Wrap the SPP bytes with the SDK and drop the registry index byte.
    let instruction = Deposit {
        ring,
        tree,
        depositor,
        deposits,
        proof: Some(to_instruction_proof(proof).expect("instruction proof")),
        escrow: EscrowBinding::Off,
        cosigner: None,
    }
    .instruction()
    .expect("audited deposit");
    let (head, rest) = instruction.data.split_at(REGISTRY_INDEX);
    let (&registry_index, spp_data) = rest.split_first().expect("registry index");
    assert_eq!(head.first(), Some(&tag::AUDITED_DEPOSIT));
    assert_eq!(registry_index, 0);
    assert_eq!(spp_data, spp.data.as_slice());
    [head, spp_data].concat()
}
