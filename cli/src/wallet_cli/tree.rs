use anyhow::{anyhow, Result};
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::{CreateProtocolConfig, CreateTree},
    state::nullifier_tree_params,
};
use zolana_transaction::Address;

use super::{
    material::load_sender_from_resolved_sync, resolve::resolve_sync, util::fetch_protocol_config,
};
use crate::{args::CreateTreeOptions, cli_config::CliConfigFile};

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
            let ix = CreateProtocolConfig {
                authority,
                protocol_authority: authority_address,
                tree_creation_authority: authority_address,
                tree_creation_is_permissionless: false,
                forester_authority: authority_address,
                ring_creation_authority: authority_address,
                ring_creation_is_permissionless: false,
                spl_interface_creation_is_permissionless: false,
            }
            .instruction();
            let signature =
                rpc.create_and_send_transaction(&[ix], authority_address, &[&material.funding])?;
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
