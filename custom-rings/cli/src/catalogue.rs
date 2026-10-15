//! Curator rings a policy reads lists from, bundled per cluster and discovered on chain.

use std::{collections::BTreeMap, path::Path};

use anyhow::{ensure, Context as _, Result};
use custom_ring_interface::RingAccount;
use custom_ring_sdk::{CustomRing, PolicyConfig};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use zolana_client::{ProgramAccountsFilter, Rpc, SolanaRpc};
use zolana_interface::{
    pda,
    state::{discriminator::RING_CONFIG, RingConfig as SppRingConfig},
};
use zolana_ring_policy::ListId;

use crate::{
    config::{Base58Address, PerCluster, Target},
    file,
    policy::ListName,
    Context,
};

const BUNDLED: &str = include_str!("../catalogue.toml");

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Catalogue {
    curators: PerCluster<BTreeMap<String, Curator>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Curator {
    pub program: Base58Address,
    /// Served from the curator's own entries.
    pub lists: Vec<ListName>,
    pub address_tree: Base58Address,
}

impl Catalogue {
    pub fn bundled() -> Result<Self> {
        toml::from_str(BUNDLED).context("the bundled catalogue does not parse")
    }

    /// A path or an http(s) URL replaces the bundled file.
    pub fn load(source: Option<&str>) -> Result<Self> {
        let Some(location) = source else {
            return Self::bundled();
        };
        let text = if location.starts_with("http://") || location.starts_with("https://") {
            reqwest::blocking::get(location)
                .and_then(reqwest::blocking::Response::error_for_status)
                .and_then(reqwest::blocking::Response::text)
                .with_context(|| format!("cannot download the catalogue at {location}"))?
        } else {
            file::read(Path::new(location))?
        };
        toml::from_str(&text).with_context(|| format!("cannot parse the catalogue at {location}"))
    }

    pub fn curators(&self, target: Target) -> &BTreeMap<String, Curator> {
        self.curators.get(target)
    }

    /// The chain's lists and tree win, a ring without a bundled name joins under its program id.
    pub fn merge(&mut self, target: Target, discovered: impl IntoIterator<Item = Curator>) {
        let curators = self.curators.get_mut(target);
        for curator in discovered {
            let name = curators
                .iter()
                .find(|(_, known)| known.program == curator.program)
                .map_or_else(|| curator.program.to_string(), |(name, _)| name.clone());
            curators.insert(name, curator);
        }
    }

    pub fn serving(
        &self,
        target: Target,
        list: ListName,
        tree: Address,
    ) -> impl Iterator<Item = (&str, &Curator)> {
        self.curators(target)
            .iter()
            .filter(move |(_, curator)| {
                curator.lists.contains(&list) && curator.address_tree.0 == tree
            })
            .map(|(name, curator)| (name.as_str(), curator))
    }

    /// A program id as given, a name through the cluster's table.
    pub fn resolve(&self, target: Target, text: &str) -> Result<CustomRing> {
        if let Ok(program) = text.parse::<Address>() {
            return Ok(CustomRing::new(program));
        }
        let curator = self.curators(target).get(text).with_context(|| {
            format!("{text} is neither a program id nor a {target} catalogue name")
        })?;
        Ok(CustomRing::new(curator.program.0))
    }
}

/// Every ring the shielded pool registered that pins a policy.
pub fn discover(rpc: &SolanaRpc) -> Result<Vec<Curator>> {
    let filter = ProgramAccountsFilter::new(SppRingConfig::SIZE).with_memcmp(0, [RING_CONFIG]);
    let accounts = rpc.get_program_accounts_filtered(pda::shielded_pool_program_id(), &filter)?;
    let data = accounts
        .iter()
        .map(|(address, account)| (*address, &account.data[..]));
    let mut curators = Vec::new();
    for ring in registered_rings(data)?.into_iter().map(CustomRing::new) {
        let (address, program) = (ring.policy_config_pda(), ring.program_id());
        if let Some(account) = rpc.get_account(address)? {
            let config = PolicyConfig::decode(&account.owner, &program, &account.data);
            let invalid = || format!("{address} is not a policy config of {program}");
            curators.push(curator_of(ring, &config.with_context(invalid)?));
        }
    }
    Ok(curators)
}

/// The ring programs behind the shielded pool's ring configs.
pub fn registered_rings<'a>(
    accounts: impl IntoIterator<Item = (Address, &'a [u8])>,
) -> Result<Vec<Address>> {
    accounts
        .into_iter()
        .map(|(address, data)| {
            bytemuck::try_from_bytes::<SppRingConfig>(data)
                .ok()
                .filter(|config| config.has_discriminator())
                .map(|config| config.program_id)
                .with_context(|| format!("{address} is not a ring config of the shielded pool"))
        })
        .collect()
}

/// The lists a ring serves from its own entries.
pub fn curator_of(ring: CustomRing, config: &PolicyConfig) -> Curator {
    let own = ring.namespace_pda();
    Curator {
        program: Base58Address(ring.program_id()),
        lists: ListName::ALL
            .into_iter()
            .filter(|list| config.source_for(list.id()) == Some(own))
            .collect(),
        address_tree: Base58Address(config.address_tree),
    }
}

/// The curator must serve `list` from its own entries in the ring's tree.
pub fn check_curator(
    ctx: &Context,
    curator: CustomRing,
    list: ListId,
    tree: Address,
) -> Result<()> {
    let program = curator.program_id();
    let deployed = ctx.rpc().get_account(program)?.is_some();
    ensure!(deployed, "curator {program} is not deployed");
    let config = ctx
        .block(curator.policy_config(ctx.chain()))?
        .with_context(|| format!("curator {program} has no policy config"))?;
    ensure!(
        config.source_for(list) == Some(curator.namespace_pda()),
        "curator {program} does not serve the {} list from its own entries",
        list.name()
    );
    ensure!(
        config.address_tree == tree,
        "curator {program} claims its addresses in tree {}, the ring uses {tree}",
        config.address_tree
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::{SourceSlot, N_SOURCE_SLOTS, POLICY_CONFIG};
    use zolana_ring_policy::EncodedRuleTable;

    use super::*;

    const RING: Address = Address::new_from_array([7u8; 32]);
    const TREE: Address = Address::new_from_array([5u8; 32]);

    fn catalogue(text: &str) -> Catalogue {
        toml::from_str(text).expect("catalogue")
    }

    fn curator(program: Address, lists: &[&str], tree: Address) -> Curator {
        Curator {
            program: Base58Address(program),
            lists: lists
                .iter()
                .map(|list| list.parse().expect("list"))
                .collect(),
            address_tree: Base58Address(tree),
        }
    }

    #[test]
    fn the_bundled_catalogue_parses_with_both_clusters_empty() {
        let bundled = Catalogue::bundled().expect("bundled");
        for target in Target::ALL {
            assert!(bundled.curators(target).is_empty(), "{target:?}");
        }
    }

    #[test]
    fn discovered_rings_join_the_bundled_names_and_resolve_both_ways() {
        let mut catalogue = catalogue(&format!(
            "[devnet.desk]\nprogram = \"{RING}\"\nlists = [\"block\"]\naddress_tree = \"{TREE}\"\n\n[localnet]\n"
        ));
        let other = Address::new_from_array([8u8; 32]);
        catalogue.merge(
            Target::Devnet,
            [
                curator(RING, &["block", "frozen"], TREE),
                curator(other, &["approval"], TREE),
            ],
        );
        let desk = &catalogue.curators(Target::Devnet)["desk"];
        assert_eq!(
            desk.lists.len(),
            2,
            "the chain's lists replace the bundled ones"
        );
        assert!(catalogue
            .curators(Target::Devnet)
            .contains_key(&other.to_string()));
        assert_eq!(
            catalogue
                .serving(Target::Devnet, "frozen".parse().expect("list"), TREE)
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            ["desk"]
        );
        assert!(catalogue
            .serving(
                Target::Devnet,
                "block".parse().expect("list"),
                Address::new_from_array([6u8; 32])
            )
            .next()
            .is_none());
        assert_eq!(
            catalogue
                .resolve(Target::Devnet, "desk")
                .expect("name")
                .program_id(),
            RING
        );
        assert_eq!(
            catalogue
                .resolve(Target::Localnet, &other.to_string())
                .expect("program id")
                .program_id(),
            other
        );
        assert_eq!(
            catalogue
                .resolve(Target::Localnet, "desk")
                .expect_err("unknown on localnet")
                .to_string(),
            "desk is neither a program id nor a localnet catalogue name"
        );
    }

    #[test]
    fn a_catalogue_with_an_unknown_key_is_refused() {
        assert!(toml::from_str::<Catalogue>("[mainnet]\n").is_err());
        assert!(toml::from_str::<Catalogue>(&format!(
            "[devnet.desk]\nprogram = \"{RING}\"\nlists = [\"escrow\"]\naddress_tree = \"{TREE}\"\n"
        ))
        .is_err());
    }

    #[test]
    fn discovery_decodes_ring_configs_and_reads_the_lists_a_ring_serves_itself() {
        let ring = CustomRing::new(RING);
        let spp = SppRingConfig {
            discriminator: RING_CONFIG,
            authority: Address::new_from_array([1u8; 32]),
            program_id: RING,
            ring_authority_transact_is_enabled: 1,
            paused: 0,
            activated: 1,
            bump: 3,
        };
        let bytes = bytemuck::bytes_of(&spp).to_vec();
        let address = Address::new_from_array([2u8; 32]);
        assert_eq!(
            registered_rings([(address, bytes.as_slice())]).expect("decodes"),
            vec![RING]
        );
        let mut foreign = bytes.clone();
        foreign[0] = 0;
        assert_eq!(
            registered_rings([(address, foreign.as_slice())])
                .expect_err("foreign")
                .to_string(),
            format!("{address} is not a ring config of the shielded pool")
        );
        assert!(registered_rings([(address, &bytes[1..])]).is_err());

        let mut sources = [SourceSlot {
            list_id: 0,
            namespace: Address::default(),
        }; N_SOURCE_SLOTS];
        sources[ListId::Block.slot()] = SourceSlot {
            list_id: ListId::Block as u8,
            namespace: ring.namespace_pda(),
        };
        sources[ListId::Frozen.slot()] = SourceSlot {
            list_id: ListId::Frozen as u8,
            namespace: Address::new_from_array([9u8; 32]),
        };
        let config = PolicyConfig {
            discriminator: POLICY_CONFIG,
            policy_hash: [0u8; 32],
            address_tree: TREE,
            address_tree_id: [0; 2],
            namespace_bump: 0,
            namespace_owner_hash: [0u8; 32],
            bump: 0,
            sources,
            rules: EncodedRuleTable::default(),
            generation: 1u32.to_le_bytes(),
            generation_slot: [0u8; 8],
        };
        assert_eq!(
            curator_of(ring, &config),
            curator(RING, &["block"], TREE),
            "a list read from another curator is not served"
        );
    }
}
