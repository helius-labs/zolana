use std::{
    fs::OpenOptions,
    process::{Command, Stdio},
};

use super::{
    material::{load_sender_from_resolved_sync, WalletMaterial},
    resolve::{get_network, resolve_sync},
    sync::{sync_context, SyncContext},
};
use crate::args::{
    MergeServiceCommand, MergeServiceDisableOptions, MergeServiceNetworkOptions,
    MergeServiceRunLoopOptions, MergeServiceStartOptions, MergeServiceStopOptions,
    NetworkWalletOptions,
};
use crate::merge_service_pid::{
    merge_service_running, pid_path, stop_merge_service, MergeServicePidGuard,
};
use anyhow::{bail, Context, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    fetch_user_record_optional_checked, should_run_pre_action_merges, LocalMergeService,
    MergeServiceConfig, ProverClient, Rpc, SolanaRpc, ZolanaIndexer,
};
use zolana_keypair::SignatureType;
use zolana_transaction::Address;
use zolana_user_registry_interface::{
    instruction::{
        register, revoke_sync_delegate, set_merge_service, set_sync_delegate, update_keys,
        RegisterData, SetSyncDelegateData, UpdateKeysData,
    },
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

pub(super) fn run_merge_service_command(command: MergeServiceCommand) -> Result<()> {
    match command {
        MergeServiceCommand::Enable(opts) => enable_merge_service(opts),
        MergeServiceCommand::Disable(opts) => disable_merge_service(opts),
        MergeServiceCommand::Start(opts) => start_merge_service(opts),
        MergeServiceCommand::Stop(opts) => stop_merge_service_command(opts),
        MergeServiceCommand::Once(opts) => run_local_merge_service_once(opts),
        MergeServiceCommand::Status(opts) => status_merge_service(opts),
        MergeServiceCommand::RunLoop(opts) => run_local_merge_service_loop(opts),
    }
}

fn enable_merge_service(opts: MergeServiceNetworkOptions) -> Result<()> {
    let sync = resolve_sync(&opts.sync)?;
    let rpc = SolanaRpc::new(sync.rpc_url.clone());
    let material = load_sender_from_resolved_sync(&sync)?;
    let owner = material.funding.pubkey();
    match ensure_self_delegate_and_merge_service_enabled(&rpc, &material)? {
        Some(signature) => {
            println!("ok merge-service enabled owner={owner} signature={signature}");
        }
        None => {
            println!("ok merge-service enabled owner={owner} signature=none");
        }
    }
    Ok(())
}

fn run_local_merge_service_once(opts: MergeServiceNetworkOptions) -> Result<()> {
    let network = get_network(&network_wallet_options(&opts))?;
    let rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let mut ctx = sync_context(&opts.sync)?;
    let mut service = local_merge_service(
        &rpc,
        &indexer,
        &mut ctx,
        network.tree,
        &network.prover_url,
        MergeServiceConfig::default(),
    );
    let report = service.run_once()?;
    println!(
        "ok merge-service once owner={} submitted={} stored={}",
        ctx.material.funding.pubkey(),
        report.submitted.len(),
        report.sync.stored_utxos
    );
    Ok(())
}

fn start_merge_service(opts: MergeServiceStartOptions) -> Result<()> {
    let sync = resolve_sync(&opts.network.sync)?;
    let rpc = SolanaRpc::new(sync.rpc_url.clone());
    let material = load_sender_from_resolved_sync(&sync)?;
    let owner = material.funding.pubkey();
    if merge_service_running(&owner)? {
        bail!("merge service already running for {owner}; run `zolana wallet merge-service stop` first");
    }
    ensure_self_delegate_and_merge_service_enabled(&rpc, &material)?;

    if opts.background {
        spawn_background_merge_service(&opts, &owner)?;
        return Ok(());
    }

    run_local_merge_service_loop(MergeServiceRunLoopOptions {
        network: opts.network,
        interval_secs: opts.interval_secs,
    })
}

fn run_local_merge_service_loop(opts: MergeServiceRunLoopOptions) -> Result<()> {
    let network = get_network(&network_wallet_options(&opts.network))?;
    let rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let mut ctx = sync_context(&opts.network.sync)?;
    let owner = ctx.material.funding.pubkey();
    let guard = MergeServicePidGuard::acquire(&owner)?;
    let config = MergeServiceConfig {
        poll_interval: std::time::Duration::from_secs(opts.interval_secs.max(1)),
        ..Default::default()
    };
    let mut service = local_merge_service(
        &rpc,
        &indexer,
        &mut ctx,
        network.tree,
        &network.prover_url,
        config,
    );
    println!(
        "ok merge-service started owner={} interval_secs={} pid={} pid_file={}",
        owner,
        opts.interval_secs.max(1),
        std::process::id(),
        guard.path().display()
    );
    service.run()?;
    Ok(())
}

fn local_merge_service<'a>(
    rpc: &'a SolanaRpc,
    indexer: &'a ZolanaIndexer,
    ctx: &'a mut SyncContext,
    tree: solana_pubkey::Pubkey,
    prover_url: &str,
    config: MergeServiceConfig,
) -> LocalMergeService<'a, SolanaRpc, ZolanaIndexer, WalletMaterial> {
    LocalMergeService {
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
    }
}

fn stop_merge_service_command(opts: MergeServiceStopOptions) -> Result<()> {
    let sync = resolve_sync(&opts.sync)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let owner = material.funding.pubkey();
    if stop_merge_service(&owner)? {
        println!("ok merge-service stopped owner={owner}");
    } else {
        println!("ok merge-service stopped owner={owner} running=false");
    }
    Ok(())
}

fn disable_merge_service(opts: MergeServiceDisableOptions) -> Result<()> {
    let sync = resolve_sync(&opts.sync)?;
    let rpc = SolanaRpc::new(sync.rpc_url.clone());
    let material = load_sender_from_resolved_sync(&sync)?;
    let owner = material.funding.pubkey();
    let _ = stop_merge_service(&owner)?;
    let revoked = revoke_self_delegate_if_set(&rpc, &material)?;
    if opts.background_only {
        let record = fetch_user_record_optional_checked(&rpc, owner)?;
        let signature = if record.as_ref().is_some_and(|record| record.merge_service) {
            None
        } else {
            Some(set_merge_service_enabled(&rpc, &material, true)?)
        };
        println!(
            "ok merge-service background-disabled owner={owner} revoked_delegate={revoked} merge_enabled_signature={}",
            signature
                .map(|signature| signature.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        return Ok(());
    }

    let signature = set_merge_service_enabled(&rpc, &material, false)?;
    println!(
        "ok merge-service disabled owner={owner} signature={signature} revoked_delegate={revoked}"
    );
    Ok(())
}

fn status_merge_service(opts: MergeServiceStopOptions) -> Result<()> {
    let sync = resolve_sync(&opts.sync)?;
    let rpc = SolanaRpc::new(sync.rpc_url.clone());
    let material = load_sender_from_resolved_sync(&sync)?;
    let owner = material.funding.pubkey();
    let running = merge_service_running(&owner)?;
    let record = fetch_user_record_optional_checked(&rpc, owner)?;
    let (merge_enabled, self_delegated) = match record.as_ref() {
        Some(record) => (
            record.merge_service,
            record.sync_delegate == Some(owner.to_bytes()),
        ),
        None => (false, false),
    };
    println!(
        "ok merge-service status owner={owner} running={running} merge_enabled={merge_enabled} self_delegated={self_delegated} pid_file={}",
        pid_path(&owner).display()
    );
    Ok(())
}

fn spawn_background_merge_service(opts: &MergeServiceStartOptions, owner: &Pubkey) -> Result<()> {
    let log_path = pid_path(owner).with_extension("log");
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("failed to clone {}", log_path.display()))?;
    let mut args = vec![
        "wallet".to_string(),
        "merge-service".to_string(),
        "run-loop".to_string(),
    ];
    push_network_args(&mut args, &opts.network)?;
    args.push("--interval-secs".to_string());
    args.push(opts.interval_secs.max(1).to_string());
    let child = Command::new(std::env::current_exe()?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .context("failed to spawn merge-service background worker")?;
    println!(
        "ok merge-service start owner={owner} background=true pid={} log={}",
        child.id(),
        log_path.display()
    );
    Ok(())
}

fn push_network_args(args: &mut Vec<String>, opts: &MergeServiceNetworkOptions) -> Result<()> {
    let network = get_network(&network_wallet_options(opts))?;
    args.push("--keypair".to_string());
    args.push(network.sync.keypair_path.display().to_string());
    args.push("--rpc-url".to_string());
    args.push(network.sync.rpc_url);
    args.push("--indexer-url".to_string());
    args.push(network.sync.indexer_url);
    args.push("--tree".to_string());
    args.push(network.tree.to_string());
    args.push("--prover-url".to_string());
    args.push(network.prover_url);
    Ok(())
}

fn network_wallet_options(opts: &MergeServiceNetworkOptions) -> NetworkWalletOptions {
    NetworkWalletOptions {
        sync: opts.sync.clone(),
        tree: opts.tree.clone(),
        prover_url: opts.prover_url.clone(),
        airdrop_lamports: None,
    }
}

pub(super) fn run_pre_action_merges(
    rpc: &SolanaRpc,
    indexer: &ZolanaIndexer,
    ctx: &mut SyncContext,
    tree: solana_pubkey::Pubkey,
    prover_url: &str,
) -> Result<usize> {
    let owner = ctx.material.funding.pubkey();
    let record = fetch_user_record_optional_checked(rpc, owner)?;
    if !should_run_pre_action_merges(record.as_ref(), owner) {
        return Ok(0);
    }

    let config = MergeServiceConfig {
        max_merges_per_run: 4,
        auto_enable_registry: false,
        ..Default::default()
    };
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

fn revoke_self_delegate_if_set(rpc: &SolanaRpc, material: &WalletMaterial) -> Result<bool> {
    let owner = material.funding.pubkey();
    let Some(record) = fetch_user_record_optional_checked(rpc, owner)? else {
        return Ok(false);
    };
    if record.sync_delegate != Some(owner.to_bytes()) {
        return Ok(false);
    }
    let (user_record, _bump) = user_record_pda(&owner);
    let ix = revoke_sync_delegate(user_record, owner);
    rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(owner.to_bytes()),
        &[&material.funding],
    )?;
    Ok(true)
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

    #[test]
    fn pre_action_gate_runs_when_merge_enabled_without_self_delegate() {
        use solana_pubkey::Pubkey;
        let owner = Pubkey::new_unique();
        let record = zolana_user_registry_interface::UserRecord {
            owner: owner.to_bytes(),
            bump: 1,
            owner_p256: None,
            nullifier_pubkey: [1u8; 32],
            viewing_pubkey: [2u8; 33],
            sync_delegate: None,
            entries: Vec::new(),
            merge_service: true,
        };
        assert!(zolana_client::should_run_pre_action_merges(
            Some(&record),
            owner
        ));
    }

    #[test]
    fn pre_action_gate_skips_when_merge_disabled() {
        use solana_pubkey::Pubkey;
        let owner = Pubkey::new_unique();
        let record = zolana_user_registry_interface::UserRecord {
            owner: owner.to_bytes(),
            bump: 1,
            owner_p256: None,
            nullifier_pubkey: [1u8; 32],
            viewing_pubkey: [2u8; 33],
            sync_delegate: None,
            entries: Vec::new(),
            merge_service: false,
        };
        assert!(!zolana_client::should_run_pre_action_merges(
            Some(&record),
            owner
        ));
    }

    #[test]
    fn pre_action_gate_skips_when_self_delegated_merge_on() {
        use solana_pubkey::Pubkey;
        let owner = Pubkey::new_unique();
        let record = zolana_user_registry_interface::UserRecord {
            owner: owner.to_bytes(),
            bump: 1,
            owner_p256: None,
            nullifier_pubkey: [1u8; 32],
            viewing_pubkey: [2u8; 33],
            sync_delegate: Some(owner.to_bytes()),
            entries: Vec::new(),
            merge_service: true,
        };
        assert!(!zolana_client::should_run_pre_action_merges(
            Some(&record),
            owner
        ));
    }
}
