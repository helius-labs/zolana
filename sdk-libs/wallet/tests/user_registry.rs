use solana_account::Account;
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use zolana_client::{ClientError, Rpc};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_user_registry_interface::user_record_pda;
use zolana_wallet::build_registration_transaction_sync;

struct RegistryAbsent;

impl Rpc for RegistryAbsent {
    fn get_account(&self, _address: Address) -> Result<Option<Account>, ClientError> {
        Ok(None)
    }

    fn get_latest_blockhash(&self) -> Result<(solana_hash::Hash, u64), ClientError> {
        Ok((solana_hash::Hash::new_from_array([9u8; 32]), 1))
    }
}

fn ed25519_registration(payer: Option<Pubkey>) -> (Pubkey, solana_message::v1::Message) {
    let owner = Pubkey::new_unique();
    let keypair = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32]))
        .expect("ed25519 keypair");
    let address = keypair.shielded_address().expect("shielded address");
    let message =
        build_registration_transaction_sync(&RegistryAbsent, owner, &address, None, payer)
            .expect("build registration")
            .expect("registration required");
    let VersionedMessage::V1(message) = message else {
        panic!("expected v1 registration message");
    };
    (owner, message)
}

#[test]
fn registration_builder_uses_optional_payer_for_rent_and_fee() {
    let payer = Pubkey::new_unique();
    let (owner, message) = ed25519_registration(Some(payer));

    assert_eq!(message.header.num_required_signatures, 2);
    assert_eq!(message.header.num_readonly_signed_accounts, 1);
    assert_eq!(message.account_keys.get(..2), Some(&[payer, owner][..]));
    let [register_ix] = message.instructions.as_slice() else {
        panic!("expected only the register instruction");
    };
    let register_accounts: Vec<Pubkey> = register_ix
        .accounts
        .iter()
        .map(|&index| {
            *message
                .account_keys
                .get(usize::from(index))
                .expect("account index in range")
        })
        .collect();
    assert_eq!(
        register_accounts.get(..3),
        Some(&[user_record_pda(&owner).0, owner, payer][..])
    );
}

#[test]
fn registration_builder_defaults_payer_to_owner() {
    let (owner, message) = ed25519_registration(None);

    assert_eq!(message.account_keys.first(), Some(&owner));
    assert_eq!(message.header.num_required_signatures, 1);
    assert_eq!(message.header.num_readonly_signed_accounts, 0);
}
