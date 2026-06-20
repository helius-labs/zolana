use std::path::Path;

use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::instruction::{CreateProtocolConfig, CreateTree};
use zolana_interface::{pda, state::tree_account_size, PROGRAM_ID_PUBKEY};
use zolana_transaction::Address;

use crate::args::CreateTreeOptions;

use super::material::{load_or_create_solana_keypair, load_sender_from_sync};
use super::util::system_create_account_ix;

pub(super) fn run_create_tree(opts: CreateTreeOptions) -> Result<()> {
    let material = load_sender_from_sync(&opts.sync)?;
    let mut rpc = SolanaRpc::new(opts.sync.rpc_url);
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
            zone_creation_authority: authority_address,
            zone_creation_is_permissionless: false,
            merge_authority: authority_address,
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
        let rent = rpc.get_minimum_balance_for_rent_exemption(tree_account_size())?;
        let ixs = vec![
            system_create_account_ix(
                &authority,
                &tree_pubkey,
                rent,
                tree_account_size() as u64,
                &PROGRAM_ID_PUBKEY,
            ),
            CreateTree {
                authority,
                tree: tree_pubkey,
                owner: authority,
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

    println!("ok tree {}", tree_pubkey);
    Ok(())
}
