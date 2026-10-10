use solana_account::Account;
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use zolana_client::user_registry::{
    build_registration_transaction_sync, set_merging_enabled_instruction,
};
use zolana_client::{check_merge_record, ClientError, Rpc};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use zolana_user_registry_interface::{user_record_pda, UserRecord};

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

/// An ed25519 owner, its shielded address, and its user record.
fn merge_owner(merging_enabled: bool) -> (Pubkey, ShieldedAddress, UserRecord) {
    let keypair = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[8u8; 32]))
        .expect("ed25519 keypair");
    let address = keypair.shielded_address().expect("shielded address");
    let owner = Pubkey::new_from_array(address.signing_pubkey.as_ed25519().expect("ed25519"));
    let record = UserRecord {
        owner,
        bump: 255,
        owner_p256: None,
        nullifier_pubkey: address.nullifier_pubkey,
        viewing_pubkey: *address.viewing_pubkey.as_bytes(),
        merging_enabled,
    };
    (owner, address, record)
}

#[test]
fn a_merge_needs_merging_enabled_and_the_owners_registered_keys() {
    let (owner, address, record) = merge_owner(true);
    check_merge_record(&record, owner, &address).expect("matching record");

    let (_, _, disabled) = merge_owner(false);
    assert!(matches!(
        check_merge_record(&disabled, owner, &address),
        Err(ClientError::MergeDisabled { owner: got }) if got == owner
    ));
    let mut p256 = record.clone();
    p256.owner_p256 = Some([2u8; 33]);
    assert!(matches!(
        check_merge_record(&p256, owner, &address),
        Err(ClientError::MergeSigningKeyMismatch)
    ));
    assert!(matches!(
        check_merge_record(&record, Pubkey::new_unique(), &address),
        Err(ClientError::MergeSigningKeyMismatch)
    ));
    let mut nullifier = record.clone();
    nullifier.nullifier_pubkey = [0xff; 32];
    assert!(matches!(
        check_merge_record(&nullifier, owner, &address),
        Err(ClientError::MergeNullifierKeyMismatch)
    ));
    let mut viewing = record;
    viewing.viewing_pubkey = [0xff; 33];
    assert!(matches!(
        check_merge_record(&viewing, owner, &address),
        Err(ClientError::MergeViewingKeyMismatch { owner: got }) if got == owner
    ));
}

#[test]
fn set_merging_enabled_targets_the_owners_record() {
    let owner = Pubkey::new_unique();
    let instruction = set_merging_enabled_instruction(owner, true);
    assert_eq!(instruction.accounts[0].pubkey, user_record_pda(&owner).0);
    assert!(instruction.accounts[0].is_writable);
    assert_eq!(instruction.accounts[1].pubkey, owner);
    assert!(instruction.accounts[1].is_signer);
}
