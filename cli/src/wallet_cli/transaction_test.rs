use solana_account::Account;
use spr_client::ClientError;
use spr_keypair::{ShieldedKeypair, SigningKey};
use spr_user_registry_interface::{
    user_record_pda, user_registry_program_id, MergeEncryptionScheme, UserRecord,
};

use super::*;

struct RegistryRpc {
    account: Option<Account>,
}

impl Rpc for RegistryRpc {
    fn get_account(&self, _address: Address) -> Result<Option<Account>, ClientError> {
        Ok(self.account.clone())
    }
}

#[test]
fn unregistered_recipient_requires_explicit_public_opt_in() {
    let recipient = Address::default();
    let error =
        resolve_transfer_recipient(&RegistryRpc { account: None }, recipient, false).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "recipient {recipient} is not registered; pass --allow-public to allow a public withdrawal (reveals recipient, amount, and asset)"
        )
    );
}

#[test]
fn allow_public_permits_an_unregistered_recipient() {
    assert_eq!(
        resolve_transfer_recipient(&RegistryRpc { account: None }, Address::default(), true)
            .unwrap(),
        None
    );
}

#[test]
fn registered_recipient_stays_shielded_with_or_without_public_opt_in() {
    let keypair = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32]))
        .expect("shielded keypair");
    let address = keypair.shielded_address().unwrap();
    let recipient = Address::new_from_array(address.signing_pubkey.as_ed25519().unwrap());
    let record = UserRecord {
        owner: recipient,
        bump: user_record_pda(&recipient).1,
        nullifier_pubkey: address.nullifier_pubkey,
        viewing_pubkey: *address.viewing_pubkey.as_bytes(),
        merge_encryption: MergeEncryptionScheme::Disabled,
    };
    let mut account_data = vec![UserRecord::DISCRIMINATOR];
    account_data.extend(borsh::to_vec(&record).unwrap());
    account_data.resize(UserRecord::SIZE, 0);
    let rpc = RegistryRpc {
        account: Some(Account {
            lamports: 1,
            data: account_data,
            owner: user_registry_program_id(),
            ..Account::default()
        }),
    };
    let expected = Some(ResolvedAddress {
        owner: recipient,
        address,
        view_tag: address.signing_pubkey.confidential_view_tag().unwrap(),
    });
    for allow_public in [false, true] {
        assert_eq!(
            resolve_transfer_recipient(&rpc, recipient, allow_public).unwrap(),
            expected
        );
    }
}

#[test]
fn allow_public_does_not_hide_registry_lookup_errors() {
    struct UnavailableRpc;
    impl Rpc for UnavailableRpc {}

    for allow_public in [false, true] {
        let error = resolve_transfer_recipient(&UnavailableRpc, Address::default(), allow_public)
            .unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<ClientError>(),
                Some(ClientError::UnsupportedRpcMethod("get_account"))
            ),
            "expected the registry RPC error, got {error}"
        );
    }
}

#[test]
fn allow_public_does_not_hide_invalid_registry_records() {
    let rpc = RegistryRpc {
        account: Some(Account::default()),
    };
    for allow_public in [false, true] {
        let error = resolve_transfer_recipient(&rpc, Address::default(), allow_public).unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<ClientError>(),
                Some(ClientError::Rpc(_))
            ),
            "expected an invalid registry record error, got {error}"
        );
    }
}
