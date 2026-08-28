use std::collections::HashMap;

use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction as SolanaTransaction;
use zolana_keypair::{
    viewing_key::ViewTag, Curve, P256Pubkey, PublicKey, ShieldedAddress, ShieldedKeypair,
};
use zolana_user_registry_interface::{
    instruction::{
        p256_key_binding_message, p256_verify_instruction, register, update_keys, RegisterData,
        UpdateKeysData, P256_KEY_BINDING_MESSAGE_LEN,
    },
    state::P256_PUBKEY_LEN,
    user_record_pda, user_registry_program_id, UserRecord,
};

use crate::actions::ResolvedAddress;
use zolana_client::{
    error::ClientError,
    rpc::{AsyncRpc, Rpc},
};

/// Compact low-S P-256 ECDSA signature (`r || s`) over SHA-256 of the message
/// returned by [`p256_registration_proof_message`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256KeyBindingProof {
    pub signature: [u8; 64],
}

/// Return the exact durable association message an external P-256 signer/HSM
/// must sign before the key can be stored in `owner`'s registry record.
pub fn p256_registration_proof_message(
    owner: Pubkey,
    address: &ShieldedAddress,
) -> Result<[u8; P256_KEY_BINDING_MESSAGE_LEN], ClientError> {
    let owner_p256 = address.signing_pubkey.as_p256()?;
    let user_record = user_record_pda(&owner).0;
    Ok(p256_key_binding_message(
        &user_record,
        &owner,
        owner_p256.as_bytes(),
    ))
}

/// Derive the on-chain registry record fields from a shielded keypair: the
/// P256 owner key (only for P256-owned wallets), nullifier pubkey, and viewing
/// pubkey. Returns the exact `RegisterData` the register/update instructions take.
fn register_fields(address: &ShieldedAddress) -> Result<RegisterData, ClientError> {
    let owner_p256 = match address.signing_pubkey.curve()? {
        Curve::P256 => Some(*address.signing_pubkey.as_p256()?.as_bytes()),
        Curve::Ed25519 | Curve::Pda => None,
    };
    Ok(RegisterData {
        owner_p256,
        nullifier_pubkey: address.nullifier_pubkey,
        viewing_pubkey: *address.viewing_pubkey.as_bytes(),
    })
}

/// Publish `keypair`'s shielded keys to the on-chain user-registry directory
/// under `funding`'s pubkey, so senders who know only that Solana address route
/// transfers to the shielded path (rather than falling back to a public
/// withdrawal). Registration is optional for receiving a confidential transfer
/// to a known shielded address; it is the pubkey-addressability directory.
///
/// Idempotent: registers if no record exists, updates the record on a key
/// change, and returns `Ok(None)` if the record already matches (no transaction
/// sent). The record lives at `user_record_pda(&funding.pubkey()).0`.
///
/// `funding` must sign — the registry keys the record under its pubkey and the
/// program requires the owner's signature, so only the record's owner can
/// publish or update it.
pub fn ensure_registered<R: Rpc>(
    rpc: &R,
    funding: &dyn Signer,
    keypair: &ShieldedKeypair,
) -> Result<Option<Signature>, ClientError> {
    let owner = funding.pubkey();
    let data = register_fields(&keypair.shielded_address()?)?;
    let (user_record, _bump) = user_record_pda(&owner);
    let owner_address = Address::new_from_array(owner.to_bytes());

    if let Some(record) = fetch_user_record_optional_checked(rpc, owner)? {
        if record.owner_p256 == data.owner_p256
            && record.nullifier_pubkey == data.nullifier_pubkey
            && record.viewing_pubkey == data.viewing_pubkey
        {
            return Ok(None);
        }
        let proof = key_binding_proof(owner, keypair)?;
        let ixs = update_key_instructions(user_record, owner, &data, proof)?;
        return Ok(Some(rpc.create_and_send_transaction(
            &ixs,
            owner_address,
            &[funding],
        )?));
    }

    let proof = key_binding_proof(owner, keypair)?;
    let ixs = register_instructions(user_record, owner, data, proof)?;
    Ok(Some(rpc.create_and_send_transaction(
        &ixs,
        owner_address,
        &[funding],
    )?))
}

/// Outcome of a strict registration attempt ([`register_if_absent`]).
///
/// Unlike [`ensure_registered`], the strict path never rotates keys: a shielded
/// identity's nullifier key is fixed for its lifetime, so a record whose
/// published keys differ from the wallet is an identity conflict to surface, not
/// something to silently overwrite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StrictRegistration {
    /// No record existed; this call wrote a fresh one.
    Written(Signature),
    /// A record already existed and matches the wallet exactly; no transaction sent.
    Current,
    /// A record exists but its published keys differ from the wallet's; no
    /// transaction sent. The caller decides how to surface the conflict.
    Mismatch,
}

/// Register `keypair`'s shielded keys under `funding`'s pubkey with strict
/// semantics: write the record only when absent, treat an exactly matching
/// record as a no-op, and report a differing record as
/// [`StrictRegistration::Mismatch`] without ever calling `update_keys`. The
/// nullifier key never rotates, so overwriting a differing record would silently
/// replace an existing on-chain identity.
///
/// `funding` must sign: the program keys the record under, and requires the
/// signature of, its owner pubkey.
pub fn register_if_absent<R: Rpc>(
    rpc: &R,
    funding: &dyn Signer,
    keypair: &ShieldedKeypair,
) -> Result<StrictRegistration, ClientError> {
    let owner = funding.pubkey();
    let data = register_fields(&keypair.shielded_address()?)?;
    let (user_record, _bump) = user_record_pda(&owner);

    if let Some(record) = fetch_user_record_optional_checked(rpc, owner)? {
        let matches = record.owner_p256 == data.owner_p256
            && record.nullifier_pubkey == data.nullifier_pubkey
            && record.viewing_pubkey == data.viewing_pubkey;
        return Ok(if matches {
            StrictRegistration::Current
        } else {
            StrictRegistration::Mismatch
        });
    }

    let proof = key_binding_proof(owner, keypair)?;
    let ixs = register_instructions(user_record, owner, data, proof)?;
    let signature = rpc.create_and_send_transaction(
        &ixs,
        Address::new_from_array(owner.to_bytes()),
        &[funding],
    )?;
    Ok(StrictRegistration::Written(signature))
}

/// Build an unsigned register/update transaction for an external Solana signer.
///
/// P-256 addresses must supply a signature over
/// [`p256_registration_proof_message`]. Ed25519 addresses must pass `None`.
///
/// Returns `Ok(None)` when the on-chain record already matches `address`.
pub async fn build_registration_transaction<R: AsyncRpc>(
    rpc: &R,
    owner: Pubkey,
    address: &ShieldedAddress,
    proof: Option<P256KeyBindingProof>,
) -> Result<Option<SolanaTransaction>, ClientError> {
    let data = register_fields(address)?;
    let existing = fetch_user_record_optional_checked_async(rpc, owner).await?;
    let Some(instructions) = registration_instructions(owner, data, existing, proof)? else {
        return Ok(None);
    };
    let (blockhash, _) = rpc.get_latest_blockhash().await?;
    Ok(Some(unsigned_registration_transaction(
        owner,
        instructions,
        blockhash,
    )))
}

/// Blocking adapter for building an unsigned register/update transaction.
///
/// P-256 addresses must supply a signature over
/// [`p256_registration_proof_message`]. Ed25519 addresses must pass `None`.
pub fn build_registration_transaction_sync<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
    address: &ShieldedAddress,
    proof: Option<P256KeyBindingProof>,
) -> Result<Option<SolanaTransaction>, ClientError> {
    let data = register_fields(address)?;
    let existing = fetch_user_record_optional_checked(rpc, owner)?;
    let Some(instructions) = registration_instructions(owner, data, existing, proof)? else {
        return Ok(None);
    };
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    Ok(Some(unsigned_registration_transaction(
        owner,
        instructions,
        blockhash,
    )))
}

fn registration_instructions(
    owner: Pubkey,
    data: RegisterData,
    existing: Option<UserRecord>,
    proof: Option<P256KeyBindingProof>,
) -> Result<Option<Vec<Instruction>>, ClientError> {
    let (user_record, _bump) = user_record_pda(&owner);
    let owner_p256 = data.owner_p256;
    let registry_instruction = match existing {
        Some(record)
            if record.owner_p256 == data.owner_p256
                && record.nullifier_pubkey == data.nullifier_pubkey
                && record.viewing_pubkey == data.viewing_pubkey =>
        {
            return Ok(None);
        }
        Some(_) => Some(update_keys(
            user_record,
            owner,
            UpdateKeysData {
                owner_p256: data.owner_p256,
                nullifier_pubkey: data.nullifier_pubkey,
                viewing_pubkey: data.viewing_pubkey,
            },
        )),
        None => Some(register(user_record, owner, data)),
    }
    .expect("non-current registration always has an instruction");

    Ok(Some(compose_key_binding_instructions(
        user_record,
        owner,
        registry_instruction,
        owner_p256,
        proof,
    )?))
}

fn unsigned_registration_transaction(
    owner: Pubkey,
    instructions: Vec<Instruction>,
    blockhash: solana_hash::Hash,
) -> SolanaTransaction {
    let mut message = Message::new(&instructions, Some(&owner));
    message.recent_blockhash = blockhash;
    SolanaTransaction::new_unsigned(message)
}

fn key_binding_proof(
    owner: Pubkey,
    keypair: &ShieldedKeypair,
) -> Result<Option<P256KeyBindingProof>, ClientError> {
    if keypair.signing_pubkey().curve()? == Curve::Ed25519 {
        return Ok(None);
    }
    let address = keypair.shielded_address()?;
    let message = p256_registration_proof_message(owner, &address)?;
    Ok(Some(P256KeyBindingProof {
        signature: keypair.sign_message(&message)?,
    }))
}

fn compose_key_binding_instructions(
    user_record: Pubkey,
    owner: Pubkey,
    registry_instruction: Instruction,
    owner_p256: Option<[u8; 33]>,
    proof: Option<P256KeyBindingProof>,
) -> Result<Vec<Instruction>, ClientError> {
    match (owner_p256, proof) {
        (Some(owner_p256), Some(proof)) => {
            let message = p256_key_binding_message(&user_record, &owner, &owner_p256);
            Ok(vec![
                p256_verify_instruction(&message, &proof.signature, &owner_p256),
                registry_instruction,
            ])
        }
        (Some(_), None) => Err(ClientError::MissingRegistryP256Proof),
        (None, Some(_)) => Err(ClientError::UnexpectedRegistryP256Proof),
        (None, None) => Ok(vec![registry_instruction]),
    }
}

fn update_key_instructions(
    user_record: Pubkey,
    owner: Pubkey,
    data: &RegisterData,
    proof: Option<P256KeyBindingProof>,
) -> Result<Vec<Instruction>, ClientError> {
    let ix = update_keys(
        user_record,
        owner,
        UpdateKeysData {
            owner_p256: data.owner_p256,
            nullifier_pubkey: data.nullifier_pubkey,
            viewing_pubkey: data.viewing_pubkey,
        },
    );
    compose_key_binding_instructions(user_record, owner, ix, data.owner_p256, proof)
}

fn register_instructions(
    user_record: Pubkey,
    owner: Pubkey,
    data: RegisterData,
    proof: Option<P256KeyBindingProof>,
) -> Result<Vec<Instruction>, ClientError> {
    let owner_p256 = data.owner_p256;
    let ix = register(user_record, owner, data);
    compose_key_binding_instructions(user_record, owner, ix, owner_p256, proof)
}

pub fn fetch_user_record_checked<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<UserRecord, ClientError> {
    let (record_pda, bump) = user_record_pda(&owner);
    let account = rpc
        .get_account(Address::new_from_array(record_pda.to_bytes()))?
        .ok_or(ClientError::UserRegistryRecordNotFound {
            owner,
            record: record_pda,
        })?;
    parse_user_record_account(owner, record_pda, bump, &account)
}

pub fn fetch_user_record_optional_checked<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<Option<UserRecord>, ClientError> {
    let (record_pda, bump) = user_record_pda(&owner);
    let Some(account) = rpc.get_account(Address::new_from_array(record_pda.to_bytes()))? else {
        return Ok(None);
    };
    Ok(Some(parse_user_record_account(
        owner, record_pda, bump, &account,
    )?))
}

pub async fn fetch_user_record_optional_checked_async<R: AsyncRpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<Option<UserRecord>, ClientError> {
    let (record_pda, bump) = user_record_pda(&owner);
    let Some(account) = rpc
        .get_account(Address::new_from_array(record_pda.to_bytes()))
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(parse_user_record_account(
        owner, record_pda, bump, &account,
    )?))
}

/// Reads the whole registry. A record this version cannot decode is skipped.
pub fn fetch_viewing_key_owners<R: Rpc>(
    rpc: &R,
) -> Result<HashMap<[u8; P256_PUBKEY_LEN], Pubkey>, ClientError> {
    Ok(index_viewing_keys(rpc.get_program_accounts(
        Address::new_from_array(user_registry_program_id().to_bytes()),
    )?))
}

pub async fn fetch_viewing_key_owners_async<R: AsyncRpc>(
    rpc: &R,
) -> Result<HashMap<[u8; P256_PUBKEY_LEN], Pubkey>, ClientError> {
    Ok(index_viewing_keys(
        rpc.get_program_accounts(Address::new_from_array(
            user_registry_program_id().to_bytes(),
        ))
        .await?,
    ))
}

fn index_viewing_keys(
    accounts: Vec<(Address, solana_account::Account)>,
) -> HashMap<[u8; P256_PUBKEY_LEN], Pubkey> {
    accounts
        .iter()
        .filter_map(|(_, account)| decode_user_record_account(account).ok())
        .map(|record| {
            (
                record.viewing_pubkey,
                Pubkey::new_from_array(record.owner.to_bytes()),
            )
        })
        .collect()
}

pub fn decode_user_record_account(
    account: &solana_account::Account,
) -> Result<UserRecord, ClientError> {
    if account.owner != user_registry_program_id() {
        return Err(ClientError::Rpc(
            "user record account is not owned by the user registry program".to_string(),
        ));
    }
    UserRecord::try_from_account_data(&account.data).map_err(|err| {
        ClientError::Rpc(format!("invalid user registry record account data: {err}"))
    })
}

fn parse_user_record_account(
    owner: Pubkey,
    record_pda: Pubkey,
    bump: u8,
    account: &solana_account::Account,
) -> Result<UserRecord, ClientError> {
    let record = decode_user_record_account(account)?;
    if record.owner.to_bytes() != owner.to_bytes() {
        return Err(ClientError::Rpc(format!(
            "user registry record {record_pda} stores a different owner than {owner}"
        )));
    }
    if record.bump != bump {
        return Err(ClientError::Rpc(format!(
            "user registry record {record_pda} stores non-canonical bump {} instead of {bump}",
            record.bump
        )));
    }
    Ok(record)
}

pub fn validate_registered_keypair<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
    keypair: &ShieldedKeypair,
) -> Result<(), ClientError> {
    let record = fetch_user_record_checked(rpc, owner)?;
    let expected_owner_p256 = match keypair.signing_pubkey().curve()? {
        Curve::P256 => Some(*keypair.signing_pubkey().as_p256()?.as_bytes()),
        Curve::Ed25519 | Curve::Pda => None,
    };
    let expected_nullifier = keypair.nullifier_key.pubkey()?;
    let expected_viewing = *keypair.viewing_pubkey().as_bytes();
    if record.owner_p256 != expected_owner_p256
        || record.nullifier_pubkey != expected_nullifier
        || record.viewing_pubkey != expected_viewing
    {
        return Err(ClientError::AddressResolution(format!(
            "user registry record for {owner} does not match the local wallet"
        )));
    }
    Ok(())
}

pub fn resolve_registered_address<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<ResolvedAddress, ClientError> {
    let record = fetch_user_record_checked(rpc, owner)
        .map_err(|err| ClientError::AddressResolution(err.to_string()))?;
    resolved_address_from_record(owner, &record)
        .map_err(|err| ClientError::AddressResolution(err.to_string()))
}

pub fn try_resolve_registered_address<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<Option<ResolvedAddress>, ClientError> {
    let Some(record) = fetch_user_record_optional_checked(rpc, owner)? else {
        return Ok(None);
    };
    Ok(Some(resolved_address_from_record(owner, &record).map_err(
        |err| ClientError::AddressResolution(err.to_string()),
    )?))
}

pub async fn try_resolve_registered_address_async<R: AsyncRpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<Option<ResolvedAddress>, ClientError> {
    let Some(record) = fetch_user_record_optional_checked_async(rpc, owner).await? else {
        return Ok(None);
    };
    Ok(Some(resolved_address_from_record(owner, &record).map_err(
        |err| ClientError::AddressResolution(err.to_string()),
    )?))
}

/// Returns whether `owner` has an on-chain user-registry record.
pub async fn is_wallet_registered<R: AsyncRpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<bool, ClientError> {
    Ok(fetch_user_record_optional_checked_async(rpc, owner)
        .await?
        .is_some())
}

/// Blocking adapter for CLI and unit-test flows.
pub fn is_wallet_registered_sync<R: Rpc>(rpc: &R, owner: Pubkey) -> Result<bool, ClientError> {
    Ok(fetch_user_record_optional_checked(rpc, owner)?.is_some())
}

/// Confidential output view tag for a transfer recipient.
///
/// Registered owners use their shielded signing pubkey tag. Unregistered owners
/// (public withdrawals) use the zero tag.
pub async fn recipient_confidential_view_tag<R: AsyncRpc>(
    rpc: &R,
    recipient: Pubkey,
) -> Result<ViewTag, ClientError> {
    let Some(record) = fetch_user_record_optional_checked_async(rpc, recipient).await? else {
        return Ok([0u8; 32]);
    };
    signing_pubkey_from_record(recipient, &record)?
        .confidential_view_tag()
        .map_err(|err| ClientError::AddressResolution(err.to_string()))
}

/// Blocking adapter for [`recipient_confidential_view_tag`].
pub fn recipient_confidential_view_tag_sync<R: Rpc>(
    rpc: &R,
    recipient: Pubkey,
) -> Result<ViewTag, ClientError> {
    let Some(record) = fetch_user_record_optional_checked(rpc, recipient)? else {
        return Ok([0u8; 32]);
    };
    signing_pubkey_from_record(recipient, &record)?
        .confidential_view_tag()
        .map_err(|err| ClientError::AddressResolution(err.to_string()))
}

fn signing_pubkey_from_record(
    owner: Pubkey,
    record: &UserRecord,
) -> Result<PublicKey, ClientError> {
    Ok(match record.owner_p256 {
        Some(owner_p256) => PublicKey::from_p256(
            &P256Pubkey::from_bytes(owner_p256)
                .map_err(|err| ClientError::AddressResolution(err.to_string()))?,
        ),
        None => PublicKey::from_ed25519(&owner.to_bytes()),
    })
}

pub fn resolved_address_from_record(
    owner: Pubkey,
    record: &UserRecord,
) -> Result<ResolvedAddress, ClientError> {
    let signing_pubkey = signing_pubkey_from_record(owner, record)?;
    let viewing_pubkey = P256Pubkey::from_bytes(record.viewing_pubkey)?;
    Ok(ResolvedAddress {
        owner,
        address: ShieldedAddress {
            signing_pubkey,
            nullifier_pubkey: record.nullifier_pubkey,
            viewing_pubkey,
        },
        view_tag: viewing_pubkey.x(),
    })
}

#[cfg(test)]
mod tests {
    use borsh::to_vec;
    use solana_account::Account;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use zolana_keypair::{ShieldedKeypair, SigningKey};
    use zolana_user_registry_interface::user_registry_program_id;

    use super::*;

    #[derive(Default)]
    struct MockRpc {
        account: Option<(Address, Account)>,
    }

    impl Rpc for MockRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok(self
                .account
                .as_ref()
                .and_then(|(expected, account)| (*expected == address).then(|| account.clone())))
        }

        fn get_latest_blockhash(&self) -> Result<(solana_hash::Hash, u64), ClientError> {
            Ok((solana_hash::Hash::new_from_array([9u8; 32]), 1))
        }
    }

    #[async_trait::async_trait]
    impl AsyncRpc for MockRpc {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Rpc::get_account(self, address)
        }

        async fn get_latest_blockhash(&self) -> Result<(solana_hash::Hash, u64), ClientError> {
            Rpc::get_latest_blockhash(self)
        }
    }

    fn account_data(record: &UserRecord) -> Vec<u8> {
        let mut data = vec![UserRecord::DISCRIMINATOR];
        data.extend_from_slice(&to_vec(record).expect("serialize user record"));
        data.resize(UserRecord::SIZE, 0);
        data
    }

    fn user_record(owner: Pubkey, bump: u8) -> UserRecord {
        UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some([2u8; 33]),
            nullifier_pubkey: [3u8; 32],
            viewing_pubkey: [4u8; 33],
            merging_enabled: false,
        }
    }

    fn account_for(record: &UserRecord) -> Account {
        Account {
            lamports: 1,
            data: account_data(record),
            owner: user_registry_program_id(),
            executable: false,
            rent_epoch: 0,
        }
    }

    fn registered_record(owner: Pubkey, bump: u8, keypair: &ShieldedKeypair) -> UserRecord {
        UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some(*keypair.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: keypair.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
            merging_enabled: false,
        }
    }

    #[test]
    fn fetch_user_record_checked_reads_canonical_pda() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let record = user_record(owner, bump);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        let fetched = fetch_user_record_checked(&rpc, owner).expect("fetch user record");

        assert_eq!(fetched, record);
    }

    #[test]
    fn fetch_user_record_checked_reports_missing_record() {
        let owner = Pubkey::new_unique();
        let (pda, _) = user_record_pda(&owner);
        let rpc = MockRpc { account: None };

        let err = fetch_user_record_checked(&rpc, owner).expect_err("missing record");

        assert!(matches!(
            err,
            ClientError::UserRegistryRecordNotFound { owner: got_owner, record }
                if got_owner == owner && record == pda
        ));
    }

    #[test]
    fn fetch_user_record_optional_checked_returns_none_for_missing_record() {
        let owner = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        let record = fetch_user_record_optional_checked(&rpc, owner).expect("optional fetch");

        assert_eq!(record, None);
    }

    #[test]
    fn registration_builder_returns_unsigned_transaction_for_external_signer() {
        let owner = Pubkey::new_unique();
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let proof = P256KeyBindingProof {
            signature: keypair
                .sign_message(
                    &p256_registration_proof_message(
                        owner,
                        &keypair.shielded_address().expect("shielded address"),
                    )
                    .expect("proof message"),
                )
                .expect("proof signature"),
        };
        let transaction = build_registration_transaction_sync(
            &MockRpc::default(),
            owner,
            &keypair.shielded_address().expect("shielded address"),
            Some(proof),
        )
        .expect("build registration")
        .expect("registration required");

        assert_eq!(transaction.message.account_keys[0], owner);
        assert_eq!(
            transaction.message.recent_blockhash,
            solana_hash::Hash::new_from_array([9u8; 32])
        );
        assert_eq!(transaction.signatures, vec![Signature::default()]);
        assert_eq!(transaction.message.instructions.len(), 2);
        let precompile_program = transaction.message.account_keys
            [usize::from(transaction.message.instructions[0].program_id_index)];
        let registry_program = transaction.message.account_keys
            [usize::from(transaction.message.instructions[1].program_id_index)];
        assert_eq!(
            precompile_program.to_bytes(),
            zolana_user_registry_interface::SECP256R1_PROGRAM_ID
        );
        assert_eq!(registry_program, user_registry_program_id());
    }

    #[test]
    fn registration_builder_requires_p256_proof() {
        let owner = Pubkey::new_unique();
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let address = keypair.shielded_address().expect("shielded address");

        let error = build_registration_transaction_sync(&MockRpc::default(), owner, &address, None)
            .expect_err("P256 registration without proof must fail");

        assert!(matches!(error, ClientError::MissingRegistryP256Proof));
    }

    #[test]
    fn registration_builder_rejects_proof_for_ed25519_address() {
        let owner = Pubkey::new_unique();
        let keypair = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32]))
            .expect("ed25519 keypair");
        let address = keypair.shielded_address().expect("shielded address");
        let proof = P256KeyBindingProof {
            signature: [0u8; 64],
        };

        let error =
            build_registration_transaction_sync(&MockRpc::default(), owner, &address, Some(proof))
                .expect_err("Ed25519 registration with P256 proof must fail");

        assert!(matches!(error, ClientError::UnexpectedRegistryP256Proof));
    }

    #[tokio::test]
    async fn async_registration_builder_returns_sendable_unsigned_transaction() {
        let owner = Pubkey::new_unique();
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let rpc = MockRpc::default();
        let address = keypair.shielded_address().expect("shielded address");
        let proof = P256KeyBindingProof {
            signature: keypair
                .sign_message(
                    &p256_registration_proof_message(owner, &address).expect("proof message"),
                )
                .expect("proof signature"),
        };
        let future = build_registration_transaction(&rpc, owner, &address, Some(proof));
        fn assert_send<T: Send>(value: T) -> T {
            value
        }
        let transaction = assert_send(future)
            .await
            .expect("build registration")
            .expect("registration required");

        assert_eq!(transaction.message.account_keys[0], owner);
        assert_eq!(transaction.signatures, vec![Signature::default()]);
    }

    #[test]
    fn is_wallet_registered_sync_reports_registered_owner() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&user_record(owner, bump)),
            )),
        };

        assert!(is_wallet_registered_sync(&rpc, owner).expect("registered"));
    }

    #[test]
    fn is_wallet_registered_sync_reports_unregistered_owner() {
        let owner = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        assert!(!is_wallet_registered_sync(&rpc, owner).expect("unregistered"));
    }

    #[test]
    fn recipient_confidential_view_tag_sync_uses_registered_signing_pubkey() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let record = registered_record(owner, bump, &keypair);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        let tag = recipient_confidential_view_tag_sync(&rpc, owner).expect("tag");
        assert_eq!(
            tag,
            keypair
                .signing_pubkey()
                .confidential_view_tag()
                .expect("confidential tag")
        );
    }

    #[test]
    fn recipient_confidential_view_tag_sync_uses_zero_tag_for_unregistered_owner() {
        let owner = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        let tag = recipient_confidential_view_tag_sync(&rpc, owner).expect("tag");
        assert_eq!(tag, [0u8; 32]);
    }

    #[tokio::test]
    async fn is_wallet_registered_reports_registered_owner() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&user_record(owner, bump)),
            )),
        };

        assert!(is_wallet_registered(&rpc, owner).await.expect("registered"));
    }

    #[tokio::test]
    async fn is_wallet_registered_reports_unregistered_owner() {
        let owner = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        assert!(!is_wallet_registered(&rpc, owner)
            .await
            .expect("unregistered"));
    }

    #[test]
    fn resolved_address_from_record_maps_registered_keys() {
        let owner = Pubkey::new_unique();
        let (_, bump) = user_record_pda(&owner);
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let record = registered_record(owner, bump, &keypair);

        let resolved = resolved_address_from_record(owner, &record).expect("resolved address");

        assert_eq!(resolved.owner, owner);
        assert_eq!(resolved.address.signing_pubkey, keypair.signing_pubkey());
        assert_eq!(
            resolved.address.nullifier_pubkey,
            keypair.nullifier_key.pubkey().unwrap()
        );
        assert_eq!(
            resolved.address.viewing_pubkey.as_bytes(),
            keypair.viewing_pubkey().as_bytes()
        );
        assert_eq!(resolved.view_tag, keypair.recipient_bootstrap_view_tag());
    }

    #[test]
    fn resolve_registered_address_fetches_and_maps_record() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let record = registered_record(owner, bump, &keypair);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        let resolved = resolve_registered_address(&rpc, owner).expect("resolved address");

        assert_eq!(resolved.owner, owner);
        assert_eq!(resolved.address.signing_pubkey, keypair.signing_pubkey());
        assert_eq!(resolved.view_tag, keypair.recipient_bootstrap_view_tag());
    }

    #[test]
    fn validate_registered_keypair_accepts_ed25519_owner_records() {
        let owner_keypair = solana_keypair::Keypair::new();
        let seed: [u8; 32] = *owner_keypair.secret_bytes();
        let keypair = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed))
            .expect("ed25519 keypair");
        let owner = owner_keypair.pubkey();
        let (pda, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: None,
            nullifier_pubkey: keypair.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
            merging_enabled: false,
        };
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        validate_registered_keypair(&rpc, owner, &keypair).expect("valid ed25519 record");
    }

    #[test]
    fn fetch_user_record_checked_rejects_owner_mismatch() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let record = user_record(Pubkey::new_unique(), bump);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        let err = fetch_user_record_checked(&rpc, owner).expect_err("owner mismatch");

        assert!(err.to_string().contains("different owner"));
    }

    #[test]
    fn fetch_user_record_checked_rejects_wrong_account_owner() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let record = user_record(owner, bump);
        let mut account = account_for(&record);
        account.owner = Pubkey::new_unique();
        let rpc = MockRpc {
            account: Some((Address::new_from_array(pda.to_bytes()), account)),
        };

        let err = fetch_user_record_checked(&rpc, owner).expect_err("program owner mismatch");

        assert!(err.to_string().contains("not owned by the user registry"));
    }

    #[test]
    fn fetch_user_record_checked_rejects_noncanonical_bump() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let record = user_record(owner, bump.wrapping_add(1));
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        let err = fetch_user_record_checked(&rpc, owner).expect_err("bump mismatch");

        assert!(err.to_string().contains("non-canonical bump"));
    }

    #[test]
    fn decode_user_record_account_rejects_wrong_discriminator() {
        let mut account = Account {
            lamports: 1,
            data: vec![0],
            owner: user_registry_program_id(),
            executable: false,
            rent_epoch: 0,
        };
        account.data.extend_from_slice(
            &to_vec(&UserRecord {
                owner: [1u8; 32].into(),
                bump: 255,
                owner_p256: Some([4u8; 33]),
                nullifier_pubkey: [2u8; 32],
                viewing_pubkey: [3u8; 33],
                merging_enabled: false,
            })
            .expect("serialize user record"),
        );

        let err = decode_user_record_account(&account).expect_err("bad discriminator");

        assert!(err
            .to_string()
            .contains("missing user record discriminator"));
    }

    /// Mock that serves an optional record account and captures the sent
    /// transaction, so `ensure_registered`'s three branches can be asserted
    /// without a validator.
    #[derive(Default)]
    struct SendMockRpc {
        account: Option<(Address, Account)>,
        sent: std::cell::RefCell<Option<solana_transaction::Transaction>>,
    }

    impl Rpc for SendMockRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok(self
                .account
                .as_ref()
                .and_then(|(expected, account)| (*expected == address).then(|| account.clone())))
        }

        fn get_latest_blockhash(&self) -> Result<(solana_hash::Hash, u64), ClientError> {
            Ok((solana_hash::Hash::default(), 0))
        }

        fn send_transaction(
            &self,
            transaction: &solana_transaction::Transaction,
        ) -> Result<Signature, ClientError> {
            *self.sent.borrow_mut() = Some(transaction.clone());
            Ok(Signature::default())
        }
    }

    fn account_at(owner: Pubkey, record: &UserRecord) -> (Address, Account) {
        let (pda, _bump) = user_record_pda(&owner);
        (Address::new_from_array(pda.to_bytes()), account_for(record))
    }

    fn ensure_registered_ix_tag(rpc: &SendMockRpc) -> u8 {
        let transaction = rpc.sent.borrow();
        let transaction = transaction.as_ref().expect("a tx was sent");
        transaction
            .message
            .instructions
            .iter()
            .find(|instruction| {
                transaction.message.account_keys[usize::from(instruction.program_id_index)]
                    == user_registry_program_id()
            })
            .expect("registry instruction")
            .data[0]
    }

    #[test]
    fn ensure_registered_registers_when_absent() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let rpc = SendMockRpc::default(); // no record -> register path
        let sig = ensure_registered(&rpc, &funding, &keypair).expect("ensure_registered");
        assert!(sig.is_some(), "register should send a transaction");
        // Tag 0 = register (first user-registry instruction tag).
        assert_eq!(
            ensure_registered_ix_tag(&rpc),
            zolana_user_registry_interface::instruction::discriminator::REGISTER
        );
    }

    #[test]
    fn ensure_registered_noops_when_current() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let owner = funding.pubkey();
        let (_pda, bump) = user_record_pda(&owner);
        let record = registered_record(owner, bump, &keypair);
        let rpc = SendMockRpc {
            account: Some(account_at(owner, &record)),
            ..Default::default()
        };
        let sig = ensure_registered(&rpc, &funding, &keypair).expect("ensure_registered");
        assert!(sig.is_none(), "matching record must not send a transaction");
        assert!(rpc.sent.borrow().is_none());
    }

    #[test]
    fn ensure_registered_updates_when_keys_changed() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let owner = funding.pubkey();
        let (_pda, bump) = user_record_pda(&owner);
        // Record exists but with stale keys (a different keypair).
        let stale = registered_record(owner, bump, &ShieldedKeypair::new_p256().unwrap());
        let rpc = SendMockRpc {
            account: Some(account_at(owner, &stale)),
            ..Default::default()
        };
        let sig = ensure_registered(&rpc, &funding, &keypair).expect("ensure_registered");
        assert!(
            sig.is_some(),
            "key change should send an update transaction"
        );
        assert_eq!(
            ensure_registered_ix_tag(&rpc),
            zolana_user_registry_interface::instruction::discriminator::UPDATE_KEYS
        );
    }

    #[test]
    fn register_if_absent_writes_when_absent() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let rpc = SendMockRpc::default(); // no record -> register path
        let outcome = register_if_absent(&rpc, &funding, &keypair).expect("register_if_absent");
        assert!(matches!(outcome, StrictRegistration::Written(_)));
        assert_eq!(
            ensure_registered_ix_tag(&rpc),
            zolana_user_registry_interface::instruction::discriminator::REGISTER
        );
    }

    #[test]
    fn register_if_absent_is_current_when_matching() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let owner = funding.pubkey();
        let (_pda, bump) = user_record_pda(&owner);
        let record = registered_record(owner, bump, &keypair);
        let rpc = SendMockRpc {
            account: Some(account_at(owner, &record)),
            ..Default::default()
        };
        let outcome = register_if_absent(&rpc, &funding, &keypair).expect("register_if_absent");
        assert_eq!(outcome, StrictRegistration::Current);
        assert!(rpc.sent.borrow().is_none());
    }

    #[test]
    fn register_if_absent_reports_mismatch_without_sending() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let owner = funding.pubkey();
        let (_pda, bump) = user_record_pda(&owner);
        // A record exists but with a different identity's keys. Strict semantics
        // must surface the conflict and never send an update_keys transaction.
        let other = registered_record(owner, bump, &ShieldedKeypair::new_p256().unwrap());
        let rpc = SendMockRpc {
            account: Some(account_at(owner, &other)),
            ..Default::default()
        };
        let outcome = register_if_absent(&rpc, &funding, &keypair).expect("register_if_absent");
        assert_eq!(outcome, StrictRegistration::Mismatch);
        assert!(rpc.sent.borrow().is_none());
    }

    struct RegistryRpc {
        accounts: Vec<(Address, Account)>,
    }

    impl Rpc for RegistryRpc {
        fn get_program_accounts(
            &self,
            program_id: Address,
        ) -> Result<Vec<(Address, Account)>, ClientError> {
            assert_eq!(
                program_id,
                Address::new_from_array(user_registry_program_id().to_bytes())
            );
            Ok(self.accounts.clone())
        }
    }

    fn record_with_viewing_key(owner: Pubkey, viewing_pubkey: [u8; P256_PUBKEY_LEN]) -> UserRecord {
        UserRecord {
            viewing_pubkey,
            ..user_record(owner, 254)
        }
    }

    fn listed(account: Account) -> (Address, Account) {
        (
            Address::new_from_array(Pubkey::new_unique().to_bytes()),
            account,
        )
    }

    #[test]
    fn fetch_viewing_key_owners_indexes_every_readable_record() {
        let first = Pubkey::new_unique();
        let second = Pubkey::new_unique();
        let unreadable = Account {
            lamports: 1,
            data: vec![0u8; UserRecord::SIZE],
            owner: user_registry_program_id(),
            executable: false,
            rent_epoch: 0,
        };
        let rpc = RegistryRpc {
            accounts: vec![
                listed(account_for(&record_with_viewing_key(first, [7u8; 33]))),
                listed(account_for(&record_with_viewing_key(second, [8u8; 33]))),
                listed(unreadable),
            ],
        };

        let owners = fetch_viewing_key_owners(&rpc).expect("index the registry");

        // The record the discriminator rejects names no owner, the rest do.
        assert_eq!(owners.len(), 2);
        assert_eq!(owners.get(&[7u8; 33]), Some(&first));
        assert_eq!(owners.get(&[8u8; 33]), Some(&second));
    }
}
