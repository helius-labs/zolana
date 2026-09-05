use anyhow::{anyhow, Result};
use solana_keypair::{read_keypair_file, Keypair};
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::{CreateProtocolConfig, CreateTree, SetTreeFees},
    state::{default_tree_fees, nullifier_tree_params, TreeFeeSchedule},
};
use zolana_transaction::Address;

use super::{
    material::load_sender_from_resolved_sync,
    resolve::{resolve_sync, resolve_sync_with_config},
    util::fetch_protocol_config,
};
use crate::{
    args::{CreateTreeOptions, SetTreeFeesOptions},
    cli_config::{resolve_tree, CliConfigFile},
};

pub(crate) fn run_create_tree(opts: CreateTreeOptions) -> Result<()> {
    let sync = resolve_sync(&opts.sync)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let mut rpc = SolanaRpc::new(sync.rpc_url);
    if opts.airdrop_lamports > 0 {
        let signature = rpc.airdrop(&material.funding.pubkey(), opts.airdrop_lamports)?;
        println!("ok airdrop signature={signature}");
    }

    let authority = material.funding.pubkey();
    let authority_address = Address::new_from_array(authority.to_bytes());
    let protocol_config = match fetch_protocol_config(&rpc)? {
        Some(config) => config,
        None => {
            let initialization_keypair = std::env::var("ZOLANA_SPP_UPGRADE_AUTHORITY_KEYPAIR")
                .ok()
                .map(|path| {
                    read_keypair_file(&path).map_err(|error| {
                        anyhow!("read SPP upgrade authority keypair {path}: {error}")
                    })
                })
                .transpose()?;
            let initialization_authority = initialization_keypair
                .as_ref()
                .map(Keypair::pubkey)
                .unwrap_or(authority);
            let ix = CreateProtocolConfig {
                fee_payer: authority,
                initialization_authority,
                protocol_authority: authority_address,
                tree_creation_authority: authority_address,
                tree_creation_is_permissionless: false,
                forester_authority: authority_address,
                ring_creation_authority: authority_address,
                fee_authority: authority_address,
                ring_activation_is_permissionless: false,
                spl_interface_creation_is_permissionless: false,
            }
            .instruction();
            let mut signers: Vec<&dyn Signer> = vec![&material.funding];
            if let Some(initialization_keypair) = &initialization_keypair {
                if initialization_keypair.pubkey() != authority {
                    signers.push(initialization_keypair);
                }
            }
            let signature = rpc.create_and_send_transaction(&[ix], authority_address, &signers)?;
            println!("ok create_protocol_config signature={signature}");
            fetch_protocol_config(&rpc)?
                .ok_or_else(|| anyhow!("protocol config missing after creation"))?
        }
    };

    let create = CreateTree {
        payer: authority,
        authority,
        tree_id: protocol_config.next_tree_id,
        nullifier_params: nullifier_tree_params(),
        fees: default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .ok_or_else(|| anyhow!("default tree fees do not fit the zkp batch size"))?,
    };
    let tree = create.tree();
    let signature = rpc.create_and_send_transaction(
        &create.instructions(),
        authority_address,
        &[&material.funding],
    )?;
    println!("ok create_tree signature={signature}");

    let mut config = CliConfigFile::load()?;
    config.set_tree(&tree)?;
    println!("ok tree {tree}");
    Ok(())
}

pub(crate) fn run_set_tree_fees(opts: SetTreeFeesOptions) -> Result<()> {
    let config = CliConfigFile::load()?;
    let sync = resolve_sync_with_config(&opts.sync, &config)?;
    let tree = resolve_tree(opts.tree.as_deref(), &config)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let rpc = SolanaRpc::new(sync.rpc_url);
    let authority = material.funding.pubkey();
    let fees = TreeFeeSchedule {
        fee_per_nullifier: opts.fee_per_nullifier,
        append_reimbursement: opts.append_reimbursement,
        close_reimbursement: opts.close_reimbursement,
    };

    let ix = SetTreeFees {
        authority,
        tree,
        fees,
    }
    .instruction();
    let signature = rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(authority.to_bytes()),
        &[&material.funding],
    )?;
    println!("ok set_tree_fees signature={signature}");
    println!(
        "ok fees fee_per_nullifier={} append_reimbursement={} close_reimbursement={}",
        fees.fee_per_nullifier, fees.append_reimbursement, fees.close_reimbursement
    );
    Ok(())
}
