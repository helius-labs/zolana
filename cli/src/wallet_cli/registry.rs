use super::{
    material::{load_sender_from_resolved_sync, WalletMaterial},
    resolve::resolve_sync,
};
use crate::args::MergeServiceOptions;
use anyhow::{bail, Result};
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    LocalMergeService, MergeServiceConfig, ProverClient, Rpc, SolanaRpc, ZolanaIndexer,
};
use zolana_keypair::SignatureType;
use zolana_transaction::Address;
use zolana_user_registry_interface::{
    instruction::{
        register, set_merge_service, set_sync_delegate, update_keys, RegisterData,
        SetSyncDelegateData, UpdateKeysData,
    },
    user_record_pda, UserRecord,
};
use super::{
    material::{load_sender_from_resolved_sync, WalletMaterial},
    resolve::{get_network, resolve_sync},
    sync::{sync_context, SyncContext},
};
use crate::args::{MergeServiceOptions, NetworkWalletOptions};

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
    if opts.run && opts.once {
        bail!("pass either --run or --once, not both");
    }
    if opts.enabled == Some(false) && (opts.run || opts.once) {
        bail!("cannot run merge service with --enabled false");
    }

    if opts.run || opts.once {
        run_local_merge_service(opts)?;
        return Ok(());
    }

    let Some(enabled) = opts.enabled else {
        bail!("pass --enabled true/false, --once, or --run");
    };
    let sync = resolve_sync(&opts.sync)?;
    let rpc = SolanaRpc::new(sync.rpc_url.clone());
    let material = load_sender_from_resolved_sync(&sync)?;
    let owner = material.funding.pubkey();
    if enabled {
        match ensure_self_delegate_and_merge_service_enabled(&rpc, &material)? {
            Some(signature) => {
                println!("ok merge-service owner={owner} enabled=true signature={signature}");
            }
            None => {
                println!("ok merge-service owner={owner} enabled=true signature=none");
            }
        }
    } else {
        let signature = set_merge_service_enabled(&rpc, &material, false)?;
        println!("ok merge-service owner={owner} enabled=false signature={signature}");
    }
    Ok(())
}

fn run_local_merge_service(opts: MergeServiceOptions) -> Result<()> {
    let network = get_network(&NetworkWalletOptions {
        sync: opts.sync.clone(),
        tree: opts.tree.clone(),
        prover_url: opts.prover_url.clone(),
        airdrop_lamports: None,
    })?;
    let rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let mut ctx = sync_context(&opts.sync)?;
    let mut config = MergeServiceConfig::default();
    config.poll_interval = std::time::Duration::from_secs(opts.interval_secs.max(1));
    let mut service = LocalMergeService {
        chain: &rpc,
        indexer: &indexer,
        wallet: &mut ctx.wallet,
        authority: &ctx.material,
        owner_pubkey: ctx.material.owner_pubkey(),
        payer: &ctx.material.funding,
        tree: network.tree,
        assets: &ctx.assets,
        prover: ProverClient::new(network.prover_url),
        config,
    };
    if opts.once {
        let report = service.run_once()?;
        println!(
            "ok merge-service once submitted={} stored={}",
            report.submitted.len(),
            report.sync.stored_utxos
        );
        return Ok(());
    }
    println!(
        "ok merge-service run owner={} interval_secs={}",
        ctx.material.funding.pubkey(),
        opts.interval_secs.max(1)
    );
    service.run()?;
    Ok(())
}

pub(super) fn run_pre_action_merges(
    rpc: &SolanaRpc,
    indexer: &ZolanaIndexer,
    ctx: &mut SyncContext,
    tree: solana_pubkey::Pubkey,
    prover_url: &str,
) -> Result<usize> {
    let mut config = MergeServiceConfig::default();
    config.max_merges_per_run = 4;
    let mut service = LocalMergeService {
        chain: rpc,
        indexer,
        wallet: &mut ctx.wallet,
        authority: &ctx.material,
        owner_pubkey: ctx.material.owner_pubkey(),
        payer: &ctx.material.funding,
        tree,
        assets: &ctx.assets,
        prover: ProverClient::new(prover_url.to_string()),
        config,
    };
    let report = service.run_pre_action()?;
    Ok(report.submitted.len())
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

fn ensure_self_delegate_and_merge_service_enabled(
    rpc: &SolanaRpc,
    material: &WalletMaterial,
) -> Result<Option<Signature>> {
    let owner = material.funding.pubkey();
    let Some(account) = rpc.get_account(Address::new_from_array(
        user_record_pda(&owner).0.to_bytes(),
    ))?
    else {
        bail!("user registry record is missing; run `zolana wallet init` first");
    };
    let record = zolana_client::decode_user_record_account(&account)?;
    if !validate_registered_wallet(&owner, &record, material)? {
        bail!("user registry record does not match the local wallet");
    }

    let self_delegate = owner.to_bytes();
    let viewing_pubkey = *material.keypair.viewing_pubkey().as_bytes();
    let delegate_ok = record.sync_delegate == Some(self_delegate)
        && record.entries.last().is_some_and(|entry| {
            entry.delegate == self_delegate
                && entry.sync_pubkey == viewing_pubkey
                && entry.viewing_pubkey == viewing_pubkey
        });
    let merge_ok = record.merge_service;
    if delegate_ok && merge_ok {
        return Ok(None);
    }

    let (user_record, _bump) = user_record_pda(&owner);
    let mut instructions = Vec::new();
    if !delegate_ok {
        instructions.push(set_sync_delegate(
            user_record,
            owner,
            SetSyncDelegateData {
                sync_delegate: self_delegate,
                sync_pubkey: viewing_pubkey,
                viewing_pubkey,
            },
        ));
    }
    if !merge_ok {
        instructions.push(set_merge_service(user_record, owner, true));
    }
    Ok(Some(rpc.create_and_send_transaction(
        &instructions,
        Address::new_from_array(owner.to_bytes()),
        &[&material.funding],
    )?))
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
            ShieldedKeypair::from_ed25519(seed, ViewingKey::new()).expect("ed25519 keypair");
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
