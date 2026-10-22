use solana_account::Account;
use solana_keypair::Keypair;
use zolana_client::{ClientError, Rpc};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::X25519Keypair;
use zolana_squads_client::{
    seed_viewing_key_account, SquadsBackend, SquadsBackendError, ViewingKeyAccountSeed,
};
use zolana_squads_interface::types::Address;

/// Minimal Rpc that serves one account's bytes from `get_account`.
struct OneAccountRpc {
    address: Address,
    account: Option<Account>,
}

impl Rpc for OneAccountRpc {
    fn get_account(&self, address: Address) -> core::result::Result<Option<Account>, ClientError> {
        if address == self.address {
            Ok(self.account.clone())
        } else {
            Ok(None)
        }
    }
}

fn backend(
    auditor: X25519Keypair,
    vka_address: Address,
    data: Vec<u8>,
) -> SquadsBackend<OneAccountRpc, OneAccountRpc> {
    let rpc = OneAccountRpc {
        address: vka_address,
        account: Some(Account {
            lamports: 1,
            data,
            owner: Address::new_from_array([9u8; 32]),
            executable: false,
            rent_epoch: 0,
        }),
    };
    let indexer = OneAccountRpc {
        address: Address::default(),
        account: None,
    };
    SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        0,
        "http://127.0.0.1:3001",
        indexer,
        rpc,
    )
}

fn secret_bytes(secret: &X25519Keypair) -> [u8; 32] {
    *secret.secret_bytes()
}

#[test]
fn resolve_shared_key_recovers_via_auditor() {
    let shared = X25519Keypair::new();
    let ephemeral = X25519Keypair::new();
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let nullifier_secret = [11u8; 32];
    let vka_address = Address::new_from_array([42u8; 32]);
    let owner = solana_owner_identity(&[1u8; 32]).expect("owner identity");

    let vka = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array(owner),
            owner_kind: 1,
            state: 1,
            encryption_scheme: zolana_squads_interface::constants::ENCRYPTION_SCHEME_X25519_AES,
            key_nonce: 0,
        },
        &shared,
        &ephemeral,
        &nullifier_secret,
        &[],
        &[auditor_pk],
    )
    .expect("seed account");

    let backend = backend(
        auditor,
        vka_address,
        vka.serialize().expect("serialize vka"),
    );
    let resolved = backend
        .resolve_shared_key(vka_address)
        .expect("resolve shared key");

    assert_eq!(
        secret_bytes(&resolved.shared_viewing_sk),
        secret_bytes(&shared)
    );
    assert_eq!(
        resolved.nullifier_secret.as_slice(),
        nullifier_secret.get(1..).expect("low 31 bytes")
    );
    assert_eq!(resolved.account, vka);
}

#[test]
fn resolve_shared_key_rejects_wrong_auditor() {
    let shared = X25519Keypair::new();
    let ephemeral = X25519Keypair::new();
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let vka_address = Address::new_from_array([42u8; 32]);

    let vka = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array([1u8; 32]),
            owner_kind: 1,
            state: 1,
            encryption_scheme: zolana_squads_interface::constants::ENCRYPTION_SCHEME_X25519_AES,
            key_nonce: 0,
        },
        &shared,
        &ephemeral,
        &[11u8; 32],
        &[],
        &[auditor_pk],
    )
    .expect("seed account");

    let backend = backend(
        X25519Keypair::new(),
        vka_address,
        vka.serialize().expect("serialize vka"),
    );
    assert!(backend.resolve_shared_key(vka_address).is_err());
}

#[test]
fn resolve_shared_key_reports_missing_account() {
    let backend = backend(
        X25519Keypair::new(),
        Address::new_from_array([42u8; 32]),
        Vec::new(),
    );
    let missing = Address::new_from_array([43u8; 32]);
    let err = backend.resolve_shared_key(missing).err().expect("missing");
    assert!(
        matches!(err, SquadsBackendError::AccountNotFound(address) if address == missing.to_string())
    );
}

#[test]
fn resolve_shared_key_rejects_commitment_for_clamping_alias() {
    let shared = X25519Keypair::from_bytes(&[42; 32]);
    let mut alias_bytes = *shared.secret_bytes();
    alias_bytes[0] ^= 1; // RFC 7748 clamping discards this bit during ECDH.
    let alias = X25519Keypair::from_bytes(&alias_bytes);
    assert_eq!(shared.pubkey(), alias.pubkey(), "same clamped public key");
    let auditor = X25519Keypair::new();
    let address = Address::new_from_array([42; 32]);
    let mut vka = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array([1; 32]),
            owner_kind: 1,
            state: 1,
            encryption_scheme: zolana_squads_interface::constants::ENCRYPTION_SCHEME_X25519_AES,
            key_nonce: 0,
        },
        &shared,
        &X25519Keypair::new(),
        &[11; 32],
        &[],
        &[auditor.pubkey()],
    )
    .expect("seed account");
    vka.shared_viewing_key_commitment =
        zolana_squads_sdk::crypto::hash_field(&alias_bytes).expect("alias commitment");
    let error = backend(auditor, address, vka.serialize().expect("serialize vka"))
        .resolve_shared_key(address)
        .err()
        .expect("reject commitment for different raw secret");
    assert!(matches!(
        error,
        SquadsBackendError::SharedKeyCommitmentMismatch
    ));
}
