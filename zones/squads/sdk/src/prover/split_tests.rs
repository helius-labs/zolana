//! Offline unit tests for the P256 probe/finalize split and the
//! recipient-by-`owner_pk_field` refactor. None of these contact the prover
//! server: they exercise only the local (signature-free) witness assembly and the
//! pure output-hash reconstruction. The full server-backed proof round-trips are
//! covered by the localnet suites.

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use zolana_client::{
    MerkleContext, MerkleProof, NonInclusionProof, SpendProof, NULLIFIER_TREE_HEIGHT,
    STATE_TREE_HEIGHT,
};
use zolana_keypair::{P256Pubkey, PublicKey, ShieldedAddress, SigningKey};
use zolana_transaction::{Address, Data, OutputUtxo, SOL_MINT};

use crate::prover::{
    probe_squads_transfer, probe_squads_withdrawal, withdrawal::split_signature, SquadsIdentity,
    SquadsTransferInput, SquadsTransferProbe, SquadsTransferRecipient, SquadsWithdrawalInput,
    SquadsWithdrawalProbe,
};

/// A random BN254-range field element (top byte cleared so it is < the field
/// modulus and < the P-256 order).
fn random_field() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0;
    b
}

/// A random 31-byte blinding.
fn random_blinding() -> [u8; 31] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 31];
    OsRng.fill_bytes(&mut b);
    b
}

/// A structurally valid but content-arbitrary spend proof: the path lengths match
/// the tree heights so the local witness assembly accepts it (the Merkle contents
/// are never verified off-chain; the circuit checks them).
fn dummy_spend_proof() -> SpendProof {
    let ctx = MerkleContext {
        tree_type: 0,
        tree: Address::default(),
    };
    SpendProof {
        state: MerkleProof {
            leaf: [0u8; 32],
            merkle_context: ctx.clone(),
            path: vec![[0u8; 32]; STATE_TREE_HEIGHT],
            leaf_index: 0,
            root: [0u8; 32],
            root_seq: 0,
            root_index: 0,
        },
        nullifier: NonInclusionProof {
            leaf: [0u8; 32],
            merkle_context: ctx,
            path: vec![[0u8; 32]; NULLIFIER_TREE_HEIGHT],
            low_element: [0u8; 32],
            low_element_index: 0,
            high_element: [0u8; 32],
            high_element_index: 0,
            root: [0u8; 32],
            root_seq: 0,
            root_index: 0,
        },
    }
}

fn random_identity() -> SquadsIdentity {
    SquadsIdentity {
        owner_secret: SecretKey::random(&mut OsRng),
        nullifier_secret: random_field_31(),
        viewing_secret: SecretKey::random(&mut OsRng),
    }
}

/// A random 31-byte nullifier secret (a valid BN254/P-256 scalar range value).
fn random_field_31() -> [u8; 31] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 31];
    OsRng.fill_bytes(&mut b);
    b
}

fn recipient_output(signing_pubkey: PublicKey, nullifier_pubkey: [u8; 32]) -> OutputUtxo {
    OutputUtxo {
        asset: SOL_MINT,
        amount: 400,
        blinding: [3u8; 31],
        zone_program_id: Some(Address::default()),
        zone_data_hash: None,
        data_hash: None,
        owner_address: Some(ShieldedAddress {
            signing_pubkey,
            nullifier_pubkey,
            viewing_pubkey: P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key()),
        }),
        owner_tag: None,
        data: Data::default(),
    }
}

/// A recipient `OutputUtxo` addressed by a precomputed `owner_pk_field` hashes
/// (and reconstructs its `owner_hash`) identically to one addressed by the full
/// recipient signing key.
#[test]
fn recipient_owner_pk_field_hash_matches_pubkey_path() {
    let recipient_owner = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recipient_signing = PublicKey::from_p256(&recipient_owner);
    let nullifier_pubkey = random_field();

    let owner_pk_field = recipient_signing
        .owner_pk_field()
        .expect("recipient owner_pk_field");

    // The synthetic key round-trips its owner_pk_field verbatim.
    assert_eq!(
        PublicKey::from_owner_pk_field(owner_pk_field)
            .owner_pk_field()
            .expect("synthetic owner_pk_field"),
        owner_pk_field,
    );

    let from_pubkey = recipient_output(recipient_signing, nullifier_pubkey);
    let from_field = recipient_output(
        PublicKey::from_owner_pk_field(owner_pk_field),
        nullifier_pubkey,
    );

    assert_eq!(
        from_pubkey.owner_hash().expect("owner hash (pubkey)"),
        from_field.owner_hash().expect("owner hash (field)"),
    );
    assert_eq!(
        from_pubkey.hash().expect("utxo hash (pubkey)"),
        from_field.hash().expect("utxo hash (field)"),
    );
}

/// Build a valid `(2, 2)` transfer probe with random deposit blindings (the
/// derived change blinding is masked to 31 bytes, so any blinding is spendable).
fn build_transfer_probe(identity: &SquadsIdentity) -> SquadsTransferProbe {
    let asset = SOL_MINT;
    let recipient = SquadsTransferRecipient {
        owner_pk_field: random_field(),
        nullifier_pubkey: random_field(),
        viewing_pubkey: P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key()),
    };
    SquadsTransferProbe {
        owner_pubkey: P256Pubkey::from_p256(&identity.owner_secret.public_key()),
        nullifier_secret: identity.nullifier_secret,
        viewing_secret: identity.viewing_secret.clone(),
        inputs: vec![
            SquadsTransferInput {
                asset,
                amount: 700,
                blinding: random_blinding(),
                spend_proof: dummy_spend_proof(),
            },
            SquadsTransferInput {
                asset,
                amount: 300,
                blinding: random_blinding(),
                spend_proof: dummy_spend_proof(),
            },
        ],
        recipient,
        transferred: 400,
        recipient_blinding: random_blinding(),
        payer_pubkey_hash: [0u8; 32],
        expiry_unix_ts: 0,
        salt: [0u8; 16],
        sender_view_tag: [0u8; 32],
        recipient_view_tag: [0u8; 32],
        proposal: None,
        prover_url: "http://prover.invalid".to_string(),
    }
}

/// The transfer probe is deterministic and its `private_tx_hash` is
/// signature-independent: signing it (as the one-shot wrapper does) and rebuilding
/// the SPP witness with that signature yields the same `private_tx_hash`. This is
/// the invariant the probe/finalize split relies on to reproduce the one-shot.
#[test]
fn transfer_probe_deterministic_and_signature_independent() {
    let identity = random_identity();
    let probe_a = build_transfer_probe(&identity);
    // Rebuild an identical probe (same identity, inputs, recipient) to check
    // determinism; reuse the first probe's randomized fields for an exact match.
    let probe_b = SquadsTransferProbe {
        owner_pubkey: probe_a.owner_pubkey,
        nullifier_secret: probe_a.nullifier_secret,
        viewing_secret: probe_a.viewing_secret.clone(),
        inputs: probe_a
            .inputs
            .iter()
            .map(|i| SquadsTransferInput {
                asset: i.asset,
                amount: i.amount,
                blinding: i.blinding,
                spend_proof: i.spend_proof.clone(),
            })
            .collect(),
        recipient: SquadsTransferRecipient {
            owner_pk_field: probe_a.recipient.owner_pk_field,
            nullifier_pubkey: probe_a.recipient.nullifier_pubkey,
            viewing_pubkey: probe_a.recipient.viewing_pubkey,
        },
        transferred: probe_a.transferred,
        recipient_blinding: probe_a.recipient_blinding,
        payer_pubkey_hash: probe_a.payer_pubkey_hash,
        expiry_unix_ts: probe_a.expiry_unix_ts,
        salt: probe_a.salt,
        sender_view_tag: probe_a.sender_view_tag,
        recipient_view_tag: probe_a.recipient_view_tag,
        proposal: None,
        prover_url: probe_a.prover_url.clone(),
    };

    let probed_a = probe_squads_transfer(probe_a).expect("probe a");
    let probed_b = probe_squads_transfer(probe_b).expect("probe b");
    assert_eq!(
        probed_a.private_tx_hash, probed_b.private_tx_hash,
        "probe must be deterministic",
    );

    // Sign the probed private_tx_hash exactly as the one-shot wrapper does.
    let mut owner_secret_bytes = [0u8; 32];
    owner_secret_bytes.copy_from_slice(identity.owner_secret.to_bytes().as_slice());
    let signature = SigningKey::from_bytes(&owner_secret_bytes)
        .expect("owner signing key")
        .sign(&zolana_keypair::hash::sha256(&probed_a.private_tx_hash));
    let (sig_r, sig_s) = split_signature(&signature).expect("split signature");

    let rebuilt = probed_a
        .spp_private_tx_hash_for_test(sig_r, sig_s)
        .expect("rebuild signed SPP witness");
    assert_eq!(
        rebuilt, probed_a.private_tx_hash,
        "finalize must rebuild the identical private_tx_hash the sender signed",
    );
}

/// The same invariant for the `(1, 1)` withdrawal probe/finalize split.
#[test]
fn withdrawal_probe_signature_independent() {
    let identity = random_identity();
    let asset = SOL_MINT;

    let probe = SquadsWithdrawalProbe {
        owner_pubkey: P256Pubkey::from_p256(&identity.owner_secret.public_key()),
        nullifier_secret: identity.nullifier_secret,
        viewing_secret: identity.viewing_secret.clone(),
        input: SquadsWithdrawalInput {
            asset,
            amount: 1000,
            blinding: random_blinding(),
            spend_proof: dummy_spend_proof(),
        },
        withdrawn: 700,
        is_spl: false,
        user_sol_account: Address::default(),
        user_spl_token: Address::default(),
        spl_token_interface: Address::default(),
        payer_pubkey_hash: [0u8; 32],
        expiry_unix_ts: 0,
        salt: [0u8; 16],
        sender_view_tag: [0u8; 32],
        proposal: None,
        prover_url: "http://prover.invalid".to_string(),
    };

    let probed = probe_squads_withdrawal(probe).expect("withdrawal probe");

    let mut owner_secret_bytes = [0u8; 32];
    owner_secret_bytes.copy_from_slice(identity.owner_secret.to_bytes().as_slice());
    let signature = SigningKey::from_bytes(&owner_secret_bytes)
        .expect("owner signing key")
        .sign(&zolana_keypair::hash::sha256(&probed.private_tx_hash));
    let (sig_r, sig_s) = split_signature(&signature).expect("split signature");

    let rebuilt = probed
        .spp_private_tx_hash_for_test(sig_r, sig_s)
        .expect("rebuild signed SPP witness");
    assert_eq!(
        rebuilt, probed.private_tx_hash,
        "finalize must rebuild the identical private_tx_hash the owner signed",
    );
}
