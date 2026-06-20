use anyhow::{bail, Result};
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::user_registry::{
    instruction::{register, RegisterData},
    user_record_pda, UserRecord,
};

use zolana_transaction::Address;

use super::material::WalletMaterial;

pub(super) fn register_wallet_on_chain(
    rpc: &SolanaRpc,
    material: &WalletMaterial,
) -> Result<Option<Signature>> {
    let owner = material.funding.pubkey();
    if let Some(account) = rpc.get_account(Address::new_from_array(
        user_record_pda(&owner).0.to_bytes(),
    ))? {
        let record = UserRecord::try_from_account_checked(&account)?;
        validate_registered_wallet(&owner, &record, material)?;
        return Ok(None);
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

fn register_data(material: &WalletMaterial) -> Result<RegisterData> {
    Ok(RegisterData {
        owner_p256: Some(*material.keypair.signing_pubkey().as_p256()?.as_bytes()),
        nullifier_pubkey: material.keypair.nullifier_key.pubkey()?,
        viewing_pubkey: *material.keypair.viewing_pubkey().as_bytes(),
    })
}

fn validate_registered_wallet(
    owner: &solana_pubkey::Pubkey,
    record: &UserRecord,
    material: &WalletMaterial,
) -> Result<()> {
    let expected = register_data(material)?;
    if record.owner != owner.to_bytes() {
        bail!("user registry record stores a different owner than {owner}");
    }
    if record.owner_p256 != expected.owner_p256
        || record.nullifier_pubkey != expected.nullifier_pubkey
        || record.viewing_pubkey != expected.viewing_pubkey
    {
        bail!("user registry record for {owner} does not match the local wallet");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_keypair::ShieldedKeypair;

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

}
