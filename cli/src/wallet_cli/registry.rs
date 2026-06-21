use super::{
    material::{load_sender_from_resolved_sync, WalletMaterial},
    resolve::resolve_sync,
};
use crate::args::MergeServiceOptions;
use anyhow::{bail, Result};
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_keypair::SignatureType;
use zolana_transaction::Address;
use zolana_user_registry_interface::{
    instruction::{register, set_merge_service, update_keys, RegisterData, UpdateKeysData},
    user_record_pda, UserRecord,
};

pub(super) fn register_wallet_on_chain(
    rpc: &SolanaRpc,
    material: &WalletMaterial,
) -> Result<Option<Signature>> {
    let owner = material.funding.pubkey();
    if let Some(account) = rpc.get_account(Address::new_from_array(
        user_record_pda(&owner).0.to_bytes(),
    ))? {
        let record = zolana_client::decode_user_record_account(&account)?;
        if validate_registered_wallet(&owner, &record, material)? {
            return Ok(None);
        }
        let (user_record, _bump) = user_record_pda(&owner);
        let ix = update_keys(user_record, owner, update_keys_data(material)?);
        let signature = rpc.create_and_send_transaction(
            &[ix],
            Address::new_from_array(owner.to_bytes()),
            &[&material.funding],
        )?;
        return Ok(Some(signature));
    }

    let (user_record, _bump) = user_record_pda(&owner);
    let ix = register(user_record, owner, register_data(material)?);
    let signature = rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(owner.to_bytes()),
        &[&material.funding],
    )?;
    Ok(Some(signature))
}

pub(super) fn run_merge_service(opts: MergeServiceOptions) -> Result<()> {
    let sync = resolve_sync(&opts.sync)?;
    let rpc = SolanaRpc::new(sync.rpc_url.clone());
    let material = load_sender_from_resolved_sync(&sync)?;
    let owner = material.funding.pubkey();
    let signature = set_merge_service_enabled(&rpc, &material, opts.enabled)?;
    println!(
        "ok merge-service owner={} enabled={} signature={}",
        owner, opts.enabled, signature
    );
    Ok(())
}

fn set_merge_service_enabled(
    rpc: &SolanaRpc,
    material: &WalletMaterial,
    enabled: bool,
) -> Result<Signature> {
    let owner = material.funding.pubkey();
    let (user_record, _bump) = user_record_pda(&owner);
    let ix = set_merge_service(user_record, owner, enabled);
    Ok(rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(owner.to_bytes()),
        &[&material.funding],
    )?)
}

fn register_data(material: &WalletMaterial) -> Result<RegisterData> {
    let owner_p256 = match material.keypair.signing_pubkey().signature_type()? {
        SignatureType::P256 => Some(*material.keypair.signing_pubkey().as_p256()?.as_bytes()),
        SignatureType::Ed25519 => None,
    };
    Ok(RegisterData {
        owner_p256,
        nullifier_pubkey: material.keypair.nullifier_key.pubkey()?,
        viewing_pubkey: *material.keypair.viewing_pubkey().as_bytes(),
    })
}

fn update_keys_data(material: &WalletMaterial) -> Result<UpdateKeysData> {
    let data = register_data(material)?;
    Ok(UpdateKeysData {
        owner_p256: data.owner_p256,
        nullifier_pubkey: data.nullifier_pubkey,
        viewing_pubkey: data.viewing_pubkey,
    })
}

fn validate_registered_wallet(
    owner: &solana_pubkey::Pubkey,
    record: &UserRecord,
    material: &WalletMaterial,
) -> Result<bool> {
    let expected = register_data(material)?;
    if record.owner != owner.to_bytes() {
        bail!("user registry record stores a different owner than {owner}");
    }
    Ok(record.owner_p256 == expected.owner_p256
        && record.nullifier_pubkey == expected.nullifier_pubkey
        && record.viewing_pubkey == expected.viewing_pubkey)
}

#[cfg(test)]
mod tests {
    use zolana_keypair::{ShieldedKeypair, ViewingKey};

    use super::*;

    fn wallet_material() -> WalletMaterial {
        WalletMaterial {
            keypair: ShieldedKeypair::new().expect("shielded keypair"),
            funding: solana_keypair::Keypair::new(),
        }
    }

    #[test]
    fn register_data_uses_wallet_keys() {
        let material = wallet_material();
        let data = register_data(&material).expect("register data");

        assert_eq!(
            data.owner_p256,
            Some(
                *material
                    .keypair
                    .signing_pubkey()
                    .as_p256()
                    .unwrap()
                    .as_bytes()
            )
        );
        assert_eq!(
            data.nullifier_pubkey,
            material.keypair.nullifier_key.pubkey().unwrap()
        );
        assert_eq!(
            data.viewing_pubkey,
            *material.keypair.viewing_pubkey().as_bytes()
        );
    }

    #[test]
    fn register_data_uses_ed25519_owner_mode() {
        let funding = solana_keypair::Keypair::new();
        let seed = funding.secret_bytes();
        let keypair =
            ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("ed25519 keypair");
        let material = WalletMaterial { keypair, funding };

        let data = register_data(&material).expect("register data");

        assert_eq!(data.owner_p256, None);
        assert_eq!(
            data.nullifier_pubkey,
            material.keypair.nullifier_key.pubkey().unwrap()
        );
        assert_eq!(
            data.viewing_pubkey,
            *material.keypair.viewing_pubkey().as_bytes()
        );
    }
}
