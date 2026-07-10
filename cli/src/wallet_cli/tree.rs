use std::path::Path;

use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::{CreateProtocolConfig, CreateTree},
    state::{tree_account_size, ProtocolConfig},
    PROGRAM_ID_PUBKEY,
};
use zolana_transaction::Address;

use super::{
    material::{load_existing_wallet, load_or_create_solana_keypair},
    util::{fetch_protocol_config, system_create_account_ix},
};
use crate::{
    args::CreateTreeOptions,
    cli_config::{resolve_keypair_path, resolve_rpc_url, CliConfigFile},
};

pub(crate) fn run_create_tree(opts: CreateTreeOptions) -> Result<()> {
    let config = CliConfigFile::load()?;
    let keypair_path = resolve_keypair_path(opts.keypair.keypair.as_deref(), &config);
    let material = load_existing_wallet(&keypair_path)?;
    let tree_keypair = load_or_create_solana_keypair(Path::new(&opts.tree_keypair))?;
    let tree_pubkey = tree_keypair.pubkey();
    let mut rpc = SolanaRpc::new(resolve_rpc_url(None, &config));
    let authority = material.funding.pubkey();
    let authority_address = Address::new_from_array(authority.to_bytes());
    let existing_protocol_config = fetch_protocol_config(&rpc)?;
    let tree_account = rpc.get_account(Address::new_from_array(tree_pubkey.to_bytes()))?;

    if tree_account.is_none() {
        if let Some(config) = &existing_protocol_config {
            validate_tree_creation_policy(config, authority)?;
        }
    }
    if let Some(account) = &tree_account {
        validate_existing_tree(tree_pubkey, account.owner, account.data.len())?;
    }

    let protocol_config_exists = existing_protocol_config.is_some();
    let tree_exists = tree_account.is_some();

    if let Some(lamports) =
        creation_airdrop_amount(opts.airdrop_lamports, protocol_config_exists, tree_exists)
    {
        let signature = rpc.airdrop(&material.funding.pubkey(), lamports)?;
        println!("ok airdrop signature={signature}");
    }

    if !protocol_config_exists {
        let ix = CreateProtocolConfig {
            authority,
            protocol_authority: authority_address,
            tree_creation_authority: authority_address,
            tree_creation_is_permissionless: false,
            forester_authority: authority_address,
            zone_creation_authority: authority_address,
            zone_creation_is_permissionless: false,
            spl_interface_creation_is_permissionless: false,
        }
        .instruction();
        let signature =
            rpc.create_and_send_transaction(&[ix], authority_address, &[&material.funding])?;
        println!("ok create_protocol_config signature={signature}");
    }

    if !tree_exists {
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

    let mut config = CliConfigFile::load()?;
    config.set_tree(&tree_pubkey)?;
    println!("ok tree {}", tree_pubkey);
    Ok(())
}

fn validate_tree_creation_policy(config: &ProtocolConfig, authority: Pubkey) -> Result<()> {
    let authority_address = Address::new_from_array(authority.to_bytes());
    if !config.allows_permissionless_tree_creation()
        && config
            .check_tree_creation_authority(&authority_address)
            .is_err()
    {
        bail!(
            "wallet {authority} is not the configured tree-creation authority and tree creation is not permissionless"
        );
    }
    Ok(())
}

fn validate_existing_tree(tree: Pubkey, account_owner: Pubkey, data_len: usize) -> Result<()> {
    if account_owner != PROGRAM_ID_PUBKEY {
        bail!("tree {tree} has unexpected owner {account_owner}; expected {PROGRAM_ID_PUBKEY}");
    }
    let expected_len = tree_account_size();
    if data_len != expected_len {
        bail!("tree {tree} has invalid size {data_len}; expected {expected_len}");
    }
    Ok(())
}

fn creation_airdrop_amount(
    requested: Option<u64>,
    protocol_config_exists: bool,
    tree_exists: bool,
) -> Option<u64> {
    requested.filter(|amount| *amount > 0 && (!protocol_config_exists || !tree_exists))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_interface::state::discriminator::PROTOCOL_CONFIG;

    fn protocol_config(authority: Pubkey, permissionless: bool) -> ProtocolConfig {
        let authority = Address::new_from_array(authority.to_bytes());
        ProtocolConfig {
            discriminator: PROTOCOL_CONFIG,
            protocol_authority: authority,
            tree_creation_authority: authority,
            forester_authority: authority,
            zone_creation_authority: authority,
            tree_creation_is_permissionless: u8::from(permissionless),
            zone_creation_is_permissionless: 0,
            spl_interface_creation_is_permissionless: 0,
        }
    }

    #[test]
    fn airdrop_is_opt_in_and_only_used_when_creation_is_required() {
        assert_eq!(creation_airdrop_amount(None, false, false), None);
        assert_eq!(creation_airdrop_amount(Some(0), false, false), None);
        assert_eq!(creation_airdrop_amount(Some(10), false, true), Some(10));
        assert_eq!(creation_airdrop_amount(Some(10), true, false), Some(10));
        assert_eq!(creation_airdrop_amount(Some(10), true, true), None);
    }

    #[test]
    fn existing_protocol_config_enforces_tree_creation_policy() {
        let authority = Pubkey::new_unique();
        let other = Pubkey::new_unique();

        validate_tree_creation_policy(&protocol_config(authority, false), authority)
            .expect("tree authority");
        assert!(validate_tree_creation_policy(&protocol_config(authority, false), other).is_err());
        validate_tree_creation_policy(&protocol_config(authority, true), other)
            .expect("permissionless tree creation");
    }

    #[test]
    fn existing_tree_requires_program_owner_and_exact_size() {
        let tree = Pubkey::new_unique();

        validate_existing_tree(tree, PROGRAM_ID_PUBKEY, tree_account_size())
            .expect("valid tree account");
        assert!(validate_existing_tree(tree, Pubkey::new_unique(), tree_account_size()).is_err());
        assert!(validate_existing_tree(tree, PROGRAM_ID_PUBKEY, tree_account_size() - 1).is_err());
    }
}
