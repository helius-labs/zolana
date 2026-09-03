//! Curator rings a policy reads lists from, bundled per cluster and discovered on chain.

use std::{collections::BTreeMap, path::Path};

use custom_ring_sdk::{AccountReadError, CustomRing, PolicyConfig};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use thiserror::Error;
use zolana_client::{ClientError, ProgramAccountsFilter, Rpc, SolanaRpc};
use zolana_interface::{
    state::{discriminator::RING_CONFIG, RingConfig as SppRingConfig},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_ring_policy::ListId;

use crate::{
    config::{Base58Address, PerCluster, Target},
    file::{self, FileError},
    policy::{list_name, ListName},
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
    pub entries_tree: Base58Address,
}

pub struct CuratorCheck {
    pub curator: CustomRing,
    pub list: ListId,
    pub entries_tree: Address,
}

#[derive(Debug, Error)]
pub enum CatalogueError {
    #[error("the bundled catalogue does not parse")]
    Bundled(#[source] toml::de::Error),
    #[error("cannot parse the catalogue at {location}")]
    Parse {
        location: String,
        #[source]
        source: toml::de::Error,
    },
    #[error(transparent)]
    File(#[from] FileError),
    #[error("cannot download the catalogue at {url}")]
    Download {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{name} is neither a program id nor a {} catalogue name", cluster.as_str())]
    UnknownCurator { name: String, cluster: Target },
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error("{address} is not a ring config of the shielded pool")]
    InvalidRingConfig { address: Address },
}

#[derive(Debug, Error)]
pub enum CuratorError {
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error("curator {curator} is not deployed")]
    NotDeployed { curator: Address },
    #[error("curator {curator} has no policy config")]
    NoPolicy { curator: Address },
    #[error("curator {curator} does not serve the {} list from its own entries", list_name(*list))]
    DoesNotServe { curator: Address, list: ListId },
    #[error("curator {curator} keeps its entries in tree {tree}, the ring reads {expected}")]
    OtherTree {
        curator: Address,
        tree: Address,
        expected: Address,
    },
}

impl Catalogue {
    pub fn bundled() -> Result<Self, CatalogueError> {
        toml::from_str(BUNDLED).map_err(CatalogueError::Bundled)
    }

    /// A path or an http(s) URL replaces the bundled file.
    pub fn load(source: Option<&str>) -> Result<Self, CatalogueError> {
        let Some(location) = source else {
            return Self::bundled();
        };
        let text = if location.starts_with("http://") || location.starts_with("https://") {
            fetch(location)?
        } else {
            file::read(Path::new(location))?
        };
        toml::from_str(&text).map_err(|source| CatalogueError::Parse {
            location: location.to_owned(),
            source,
        })
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
                .map_or_else(|| curator.program.0.to_string(), |(name, _)| name.clone());
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
                curator.lists.contains(&list) && curator.entries_tree.0 == tree
            })
            .map(|(name, curator)| (name.as_str(), curator))
    }

    /// A program id as given, a name through the cluster's table.
    pub fn resolve(&self, target: Target, text: &str) -> Result<CustomRing, CatalogueError> {
        if let Ok(program) = text.parse::<Address>() {
            return Ok(CustomRing::new(program));
        }
        self.curators(target)
            .get(text)
            .map(|curator| CustomRing::new(curator.program.0))
            .ok_or_else(|| CatalogueError::UnknownCurator {
                name: text.to_owned(),
                cluster: target,
            })
    }
}

/// Every ring the shielded pool registered that pins a policy.
pub fn discover(rpc: &SolanaRpc) -> Result<Vec<Curator>, CatalogueError> {
    let filter = ProgramAccountsFilter::new(SppRingConfig::SIZE).with_memcmp(0, [RING_CONFIG]);
    let accounts = rpc.get_program_accounts_filtered(
        Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        &filter,
    )?;
    let rings = registered_rings(
        accounts
            .iter()
            .map(|(address, account)| (*address, account.data.as_slice())),
    )?;
    rings
        .into_iter()
        .filter_map(|program| {
            let ring = CustomRing::new(program);
            ring.read_policy_config(rpc)
                .map(|config| config.map(|config| curator_of(ring, &config)))
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// The ring programs behind the shielded pool's ring configs.
pub fn registered_rings<'a>(
    accounts: impl IntoIterator<Item = (Address, &'a [u8])>,
) -> Result<Vec<Address>, CatalogueError> {
    accounts
        .into_iter()
        .map(|(address, data)| {
            bytemuck::try_from_bytes::<SppRingConfig>(data)
                .ok()
                .filter(|config| config.has_discriminator())
                .map(|config| config.program_id)
                .ok_or(CatalogueError::InvalidRingConfig { address })
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
        entries_tree: Base58Address(config.entries_tree),
    }
}

impl CuratorCheck {
    pub fn run<R: Rpc>(&self, rpc: &R) -> Result<(), CuratorError> {
        let curator = self.curator.program_id();
        if rpc.get_account(curator)?.is_none() {
            return Err(CuratorError::NotDeployed { curator });
        }
        let config = self
            .curator
            .read_policy_config(rpc)?
            .ok_or(CuratorError::NoPolicy { curator })?;
        if config.source_for(self.list) != Some(self.curator.namespace_pda()) {
            return Err(CuratorError::DoesNotServe {
                curator,
                list: self.list,
            });
        }
        if config.entries_tree != self.entries_tree {
            return Err(CuratorError::OtherTree {
                curator,
                tree: config.entries_tree,
                expected: self.entries_tree,
            });
        }
        Ok(())
    }
}

fn fetch(url: &str) -> Result<String, CatalogueError> {
    let failed = |source| CatalogueError::Download {
        url: url.to_owned(),
        source,
    };
    reqwest::blocking::get(url)
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(reqwest::blocking::Response::text)
        .map_err(failed)
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
            entries_tree: Base58Address(tree),
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
            "[devnet.desk]\nprogram = \"{RING}\"\nlists = [\"block\"]\nentries_tree = \"{TREE}\"\n\n[localnet]\n"
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
        assert!(matches!(
            catalogue.resolve(Target::Localnet, "desk"),
            Err(CatalogueError::UnknownCurator { name, cluster: Target::Localnet }) if name == "desk"
        ));
    }

    #[test]
    fn a_catalogue_with_an_unknown_key_is_refused() {
        assert!(toml::from_str::<Catalogue>("[mainnet]\n").is_err());
        assert!(toml::from_str::<Catalogue>(&format!(
            "[devnet.desk]\nprogram = \"{RING}\"\nlists = [\"escrow\"]\nentries_tree = \"{TREE}\"\n"
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
        assert!(matches!(
            registered_rings([(address, foreign.as_slice())]),
            Err(CatalogueError::InvalidRingConfig { address: found }) if found == address
        ));
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
            entries_tree: TREE,
            namespace_bump: 0,
            bump: 0,
            sources,
            rules: EncodedRuleTable::empty(),
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
