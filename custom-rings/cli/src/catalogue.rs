//! Curator rings a policy reads lists from, bundled per cluster and discovered on chain.

use std::{collections::BTreeMap, path::Path};

use anyhow::{ensure, Context as _, Result};
use custom_ring_interface::{MemberRegistry, RingAccount};
use custom_ring_sdk::{CustomRing, ListRegistry};
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
    policy::{ListName, Pinned},
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

    /// The chain's lists win, a ring without a bundled name joins under its program id.
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
    ) -> impl Iterator<Item = (&str, &Curator)> {
        self.curators(target)
            .iter()
            .filter(move |(_, curator)| curator.lists.contains(&list))
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
        let Some(account) = rpc.get_account(ring.registry_pda())? else {
            continue;
        };
        // A registry of another layout is no curator.
        let program = ring.program_id();
        let Some(registry) = MemberRegistry::decode(&account.owner, &program, &account.data) else {
            continue;
        };
        if let Ok(Some(pinned)) = Pinned::of(Box::new(registry)) {
            curators.push(curator_of(ring, &pinned.registry));
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

/// The lists a ring serves from its own registry.
pub fn curator_of(ring: CustomRing, registry: &MemberRegistry) -> Curator {
    Curator {
        program: Base58Address(ring.program_id()),
        lists: ListName::ALL
            .into_iter()
            .filter(|list| registry.registry_for(list.id()) == Some(ListRegistry::Own))
            .collect(),
    }
}

/// The curator must pin a policy that serves `list` from its own registry.
pub fn check_curator(ctx: &Context, curator: CustomRing, list: ListId) -> Result<()> {
    let program = curator.program_id();
    let deployed = ctx.rpc().get_account(program)?.is_some();
    ensure!(deployed, "curator {program} is not deployed");
    let registry = ctx
        .block(curator.registry(ctx.chain()))?
        .with_context(|| format!("curator {program} has no member registry"))?;
    let pinned = Pinned::of(registry)
        .with_context(|| {
            format!("curator {program} pins a policy its registry does not reproduce")
        })?
        .with_context(|| format!("curator {program} pins no policy"))?;
    ensure!(
        pinned.registry.registry_for(list) == Some(ListRegistry::Own),
        "curator {program} does not serve the {} list from its own registry",
        list.name()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::SourceSlot;

    use super::*;

    const RING: Address = Address::new_from_array([7u8; 32]);

    fn catalogue(text: &str) -> Catalogue {
        toml::from_str(text).expect("catalogue")
    }

    fn curator(program: Address, lists: &[&str]) -> Curator {
        Curator {
            program: Base58Address(program),
            lists: lists
                .iter()
                .map(|list| list.parse().expect("list"))
                .collect(),
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
            "[devnet.desk]\nprogram = \"{RING}\"\nlists = [\"block\"]\n\n[localnet]\n"
        ));
        let other = Address::new_from_array([8u8; 32]);
        catalogue.merge(
            Target::Devnet,
            [
                curator(RING, &["block", "frozen"]),
                curator(other, &["approval"]),
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
                .serving(Target::Devnet, "frozen".parse().expect("list"))
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            ["desk"]
        );
        assert!(catalogue
            .serving(Target::Localnet, "frozen".parse().expect("list"))
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
            "[devnet.desk]\nprogram = \"{RING}\"\nlists = [\"escrow\"]\n"
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

        let mut registry = MemberRegistry::new(0, 0);
        registry.sources[ListId::Block.slot()] = SourceSlot {
            list_id: ListId::Block as u8,
            registry: Address::default(),
        };
        registry.sources[ListId::Frozen.slot()] = SourceSlot {
            list_id: ListId::Frozen as u8,
            registry: Address::new_from_array([9u8; 32]),
        };
        assert_eq!(
            curator_of(ring, &registry),
            curator(RING, &["block"]),
            "a list read from another curator is not served"
        );
    }
}
