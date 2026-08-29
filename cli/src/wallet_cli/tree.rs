use std::path::Path;

use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::{CreateProtocolConfig, CreateTree},
    pda,
    state::{address_tree_params, tree_account_size, tree_creation_lamports},
    NULLIFIER_PDA_SIZE, PROGRAM_ID_PUBKEY,
};
use zolana_transaction::Address;

use super::{
    material::{load_or_create_solana_keypair, load_sender_from_resolved_sync},
    resolve::resolve_sync,
    util::system_create_account_ix,
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
    let protocol_config = pda::protocol_config();
    if rpc
        .get_account(Address::new_from_array(protocol_config.to_bytes()))?
        .is_none()
    {
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
    }

    let tree_keypair = load_or_create_solana_keypair(Path::new(&opts.tree_keypair))?;
    let tree_pubkey = tree_keypair.pubkey();
    if rpc
        .get_account(Address::new_from_array(tree_pubkey.to_bytes()))?
        .is_none()
    {
        let tree_rent = rpc.get_minimum_balance_for_rent_exemption(tree_account_size())?;
        let nullifier_pda_rent = rpc.get_minimum_balance_for_rent_exemption(NULLIFIER_PDA_SIZE)?;
        let lamports =
            tree_creation_lamports(&address_tree_params(), tree_rent, nullifier_pda_rent)
                .ok_or_else(|| anyhow::anyhow!("tree creation lamports overflow u64"))?;
        let ixs = vec![
            system_create_account_ix(
                &authority,
                &tree_pubkey,
                lamports,
                tree_account_size() as u64,
                &PROGRAM_ID_PUBKEY,
            ),
            CreateTree {
                authority,
                tree: tree_pubkey,
            }
            .instruction(),
        ];
        let signature = rpc.create_and_send_transaction(
            &ixs,
            authority_address,
            &[&material.funding, &tree_keypair],
        )?;
        println!("ok create_tree signature={signature}");
    }

    let mut config = CliConfigFile::load()?;
    config.set_tree(&tree_pubkey)?;
    println!("ok tree {}", tree_pubkey);
    Ok(())
}
