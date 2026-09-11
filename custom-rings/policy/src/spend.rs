//! One spend record per member identity, spent into its successor by the member's own transfer.

use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::hash_bytes, Hasher, HasherError, Poseidon,
};

use crate::{
    entry::{entry_nullifier, ListNamespace},
    field_u64, Member, SPEND_ADDRESS_DOMAIN, SPEND_RECORD_DOMAIN,
};

pub use crate::rule_table::MAX_VELOCITY_ASSETS;

/// `member(32) || version(8) || window(8) || counters_commitment(32) || blinding(32)`.
pub const SPEND_RECORD_LEN: usize = 112;
/// `salt(32) || assets(8 x 32) || spent(8 x 8)`, the private half a sender keeps.
pub const SPEND_COUNTERS_LEN: usize = 32 + MAX_VELOCITY_ASSETS * 40;
/// The plaintext envelope byte and the length prefix in front of the record.
pub const SPEND_RECORD_OUTPUT_DATA_LEN: usize = 5 + SPEND_RECORD_LEN;

/// The ring id field a UTXO inside the ring carries, `hash_bytes` of the program address.
pub fn ring_id_field(program_id: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    hash_bytes(program_id)
}

/// One address lineage per member, the seed domain keeps it apart from every list.
pub fn spend_seed(member: &Member) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[&SPEND_ADDRESS_DOMAIN, member.as_bytes()])
}

impl ListNamespace {
    pub fn spend_address(&self, member: &Member, tree_id: u16) -> Result<[u8; 32], HasherError> {
        let seed = spend_seed(member)?;
        entry_nullifier(&self.address_utxo_hash(&seed, tree_id)?, &seed)
    }
}

/// The published half of a spend record, the counters stay in the commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendRecord {
    pub member: Member,
    pub version: u64,
    pub window: u64,
    pub counters_commitment: [u8; 32],
    pub blinding: [u8; 32],
}

impl SpendRecord {
    /// The leaf preimage, binds the record to its derived address.
    pub fn data_hash(&self, address: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &SPEND_RECORD_DOMAIN,
            address,
            self.member.as_bytes(),
            &field_u64(self.version),
            &field_u64(self.window),
            &self.counters_commitment,
        ])
    }

    pub fn utxo_hash(
        &self,
        owner: &ListNamespace,
        address: &[u8; 32],
        tree_id: u16,
    ) -> Result<[u8; 32], HasherError> {
        owner.leaf_hash(&self.data_hash(address)?, &self.blinding, tree_id)
    }

    pub fn from_record_bytes(content: &[u8]) -> Option<Self> {
        let content: &[u8; SPEND_RECORD_LEN] = content.try_into().ok()?;
        Some(Self {
            member: Member::from_bytes(content[..32].try_into().ok()?).ok()?,
            version: u64::from_le_bytes(content[32..40].try_into().ok()?),
            window: u64::from_le_bytes(content[40..48].try_into().ok()?),
            counters_commitment: content[48..80].try_into().ok()?,
            blinding: content[80..112].try_into().ok()?,
        })
    }

    pub fn to_output_data(&self) -> [u8; SPEND_RECORD_OUTPUT_DATA_LEN] {
        let mut content = [0u8; SPEND_RECORD_OUTPUT_DATA_LEN];
        content[1..5].copy_from_slice(&(SPEND_RECORD_LEN as u32).to_le_bytes());
        content[5..37].copy_from_slice(self.member.as_bytes());
        content[37..45].copy_from_slice(&self.version.to_le_bytes());
        content[45..53].copy_from_slice(&self.window.to_le_bytes());
        content[53..85].copy_from_slice(&self.counters_commitment);
        content[85..117].copy_from_slice(&self.blinding);
        content
    }
}

/// The private half, `commitment = HashChain(salt, asset_0, spent_0, .., asset_7, spent_7)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendCounters {
    pub salt: [u8; 32],
    pub assets: [[u8; 32]; MAX_VELOCITY_ASSETS],
    pub spent: [u64; MAX_VELOCITY_ASSETS],
}

impl SpendCounters {
    /// Every counter at zero under the zero salt, a registration pins it over no mints.
    pub fn zero(assets: &[[u8; 32]]) -> Self {
        let mut counters = Self {
            salt: [0u8; 32],
            assets: [[0u8; 32]; MAX_VELOCITY_ASSETS],
            spent: [0; MAX_VELOCITY_ASSETS],
        };
        for (slot, asset) in counters.assets.iter_mut().zip(assets) {
            *slot = *asset;
        }
        counters
    }

    pub fn commitment(&self) -> Result<[u8; 32], HasherError> {
        let mut elements = [[0u8; 32]; 1 + 2 * MAX_VELOCITY_ASSETS];
        elements[0] = self.salt;
        for (index, (asset, spent)) in self.assets.iter().zip(self.spent).enumerate() {
            elements[1 + 2 * index] = *asset;
            elements[2 + 2 * index] = field_u64(spent);
        }
        create_hash_chain_from_slice(&elements)
    }

    pub fn to_bytes(&self) -> [u8; SPEND_COUNTERS_LEN] {
        let mut bytes = [0u8; SPEND_COUNTERS_LEN];
        bytes[..32].copy_from_slice(&self.salt);
        for (index, (asset, spent)) in self.assets.iter().zip(self.spent).enumerate() {
            let at = 32 + index * 40;
            bytes[at..at + 32].copy_from_slice(asset);
            bytes[at + 32..at + 40].copy_from_slice(&spent.to_le_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; SPEND_COUNTERS_LEN] = bytes.try_into().ok()?;
        let mut counters = Self::zero(&[]);
        counters.salt = bytes[..32].try_into().ok()?;
        for index in 0..MAX_VELOCITY_ASSETS {
            let at = 32 + index * 40;
            counters.assets[index] = bytes[at..at + 32].try_into().ok()?;
            counters.spent[index] = u64::from_le_bytes(bytes[at + 32..at + 40].try_into().ok()?);
        }
        Some(counters)
    }

    /// The total spent in `asset`, zero for a mint the record does not carry.
    pub fn spent(&self, asset: &[u8; 32]) -> u64 {
        self.assets
            .iter()
            .zip(self.spent)
            .find(|(known, _)| *known == asset)
            .map_or(0, |(_, spent)| spent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(byte: u8) -> Member {
        Member::owner_tag(&[byte; 32]).unwrap()
    }

    #[test]
    fn a_spend_address_never_collides_with_an_entry_address() {
        let owner = ListNamespace::new(&[11u8; 32]).unwrap();
        let spend = owner.spend_address(&member(1), 3).unwrap();
        for list_id in crate::ListId::ALL {
            assert_ne!(spend, owner.address(list_id, &member(1), 3).unwrap());
        }
        assert_ne!(spend, owner.spend_address(&member(2), 3).unwrap());
        assert_ne!(spend, owner.spend_address(&member(1), 4).unwrap());
    }

    #[test]
    fn the_record_round_trips_and_binds_every_field() {
        let record = SpendRecord {
            member: member(1),
            version: 3,
            window: 9,
            counters_commitment: [5u8; 32],
            blinding: [6u8; 32],
        };
        let data = record.to_output_data();
        assert_eq!(data[0], 0);
        assert_eq!(&data[1..5], &(SPEND_RECORD_LEN as u32).to_le_bytes());
        assert_eq!(SpendRecord::from_record_bytes(&data[5..]), Some(record));
        assert_eq!(
            SpendRecord::from_record_bytes(&data[5..SPEND_RECORD_OUTPUT_DATA_LEN - 1]),
            None
        );
        let address = [7u8; 32];
        let base = record.data_hash(&address).unwrap();
        for changed in [
            SpendRecord {
                version: 4,
                ..record
            },
            SpendRecord {
                window: 10,
                ..record
            },
            SpendRecord {
                counters_commitment: [8u8; 32],
                ..record
            },
            SpendRecord {
                member: member(2),
                ..record
            },
        ] {
            assert_ne!(changed.data_hash(&address).unwrap(), base);
        }
    }

    #[test]
    fn counters_round_trip_through_their_bytes() {
        let mut counters = SpendCounters::zero(&[[1u8; 32], [2u8; 32]]);
        counters.salt = [9u8; 32];
        counters.spent[1] = u64::MAX;
        let bytes = counters.to_bytes();
        assert_eq!(SpendCounters::from_bytes(&bytes), Some(counters));
        assert_eq!(SpendCounters::from_bytes(&bytes[1..]), None);
    }

    #[test]
    fn counters_commit_to_their_mints_and_the_salt() {
        let assets = [[1u8; 32], [2u8; 32]];
        let zero = SpendCounters::zero(&assets);
        assert_eq!(zero.spent(&[1u8; 32]), 0);
        assert_eq!(zero.assets[2], [0u8; 32]);
        let mut spent = zero;
        spent.spent[1] = 42;
        assert_eq!(spent.spent(&[2u8; 32]), 42);
        assert_eq!(spent.spent(&[9u8; 32]), 0);
        assert_ne!(spent.commitment().unwrap(), zero.commitment().unwrap());
        let mut swapped = zero;
        swapped.assets.swap(0, 1);
        assert_ne!(swapped.commitment().unwrap(), zero.commitment().unwrap());
        let mut salted = zero;
        salted.salt = [3u8; 32];
        assert_ne!(salted.commitment().unwrap(), zero.commitment().unwrap());
    }
}
