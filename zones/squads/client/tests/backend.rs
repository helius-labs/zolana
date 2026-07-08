use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_account::Account;
use solana_keypair::Keypair;
use zolana_client::{ClientError, Rpc};
use zolana_keypair::P256Pubkey;
use zolana_squads_client::{seed_viewing_key_account, SquadsBackend, ViewingKeyAccountSeed};
use zolana_squads_interface::types::Address;

/// Minimal Rpc that serves one account's bytes from `get_account`.
struct OneAccountRpc {
    address: Address,
    account: Account,
}

impl Rpc for OneAccountRpc {
    fn get_account(&self, address: Address) -> core::result::Result<Option<Account>, ClientError> {
        if address == self.address {
            Ok(Some(self.account.clone()))
        } else {
            Ok(None)
        }
    }
}

#[test]
fn resolve_shared_key_recovers_via_auditor() {
    let shared = SecretKey::random(&mut OsRng);
    let ephemeral = SecretKey::random(&mut OsRng);
    let auditor = SecretKey::random(&mut OsRng);
    let auditor_pk = P256Pubkey::from_p256(&auditor.public_key());
    let nullifier_secret = [11u8; 32];
    let vka_address = Address::new_from_array([42u8; 32]);

    let vka = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array([1u8; 32]),
            owner_kind: 1,
            state: 1,
            encryption_scheme: 0,
            key_nonce: 0,
        },
        &shared,
        &ephemeral,
        &nullifier_secret,
        &[],
        &[auditor_pk],
    )
    .expect("seed account");

    let account = Account {
        lamports: 1,
        data: vka.serialize().expect("serialize vka"),
        owner: Address::new_from_array([9u8; 32]),
        executable: false,
        rent_epoch: 0,
    };
    let rpc = OneAccountRpc {
        address: vka_address,
        account,
    };

    // A distinct handle for the indexer slot; unused by resolve_shared_key.
    let indexer = OneAccountRpc {
        address: Address::default(),
        account: Account {
            lamports: 0,
            data: Vec::new(),
            owner: Address::default(),
            executable: false,
            rent_epoch: 0,
        },
    };

    let backend = SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        Address::default(),
        "http://127.0.0.1:3001",
        indexer,
        rpc,
    );

    let resolved = backend
        .resolve_shared_key(vka_address)
        .expect("resolve shared key");

    let mut shared_be = [0u8; 32];
    shared_be.copy_from_slice(shared.to_bytes().as_slice());
    let recovered_be = {
        let mut b = [0u8; 32];
        b.copy_from_slice(resolved.shared_viewing_sk.to_bytes().as_slice());
        b
    };
    assert_eq!(recovered_be, shared_be);
    assert_eq!(resolved.nullifier_secret, nullifier_secret[1..32]);
    assert_eq!(resolved.account.owner_kind, 1);
}
