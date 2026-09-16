//! One spend record lineage per member.

use core::ops::Range;

use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::hash_bytes, Hasher, HasherError,
    Poseidon, Sha256,
};

use crate::{
    entry::{entry_nullifier, Leaf, ListNamespace},
    field_u64, open_plaintext, seal_plaintext, Member, RuleTableError, MAX_VELOCITY_ASSETS,
    PLAINTEXT_ENVELOPE_LEN, SPEND_ADDRESS_DOMAIN, SPEND_RECORD_DOMAIN,
};

const MEMBER: Range<usize> = 0..32;
const VERSION: Range<usize> = 32..40;
const WINDOW: Range<usize> = 40..48;
const COMMITMENT: Range<usize> = 48..80;
const BLINDING: Range<usize> = 80..112;
const SPEND_RECORD_LEN: usize = BLINDING.end;
const SPEND_RECORD_OUTPUT_DATA_LEN: usize = PLAINTEXT_ENVELOPE_LEN + SPEND_RECORD_LEN;
const COUNTER_SLOT_LEN: usize = 32 + 8;
/// The private half a sender keeps.
pub const SPEND_COUNTERS_LEN: usize = 32 + MAX_VELOCITY_ASSETS * COUNTER_SLOT_LEN;

/// Apart from the counters message, tagged by the bare namespace.
pub fn spend_record_message_tag(namespace: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    Sha256::hashv(&[b"zolana:spend-record:v1", namespace])
}

/// The ring id field a UTXO inside the ring carries.
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
        owner.leaf_hash(
            Leaf {
                data_hash: &self.data_hash(address)?,
                blinding: &self.blinding,
            },
            tree_id,
        )
    }

    pub fn to_output_data(&self) -> [u8; SPEND_RECORD_OUTPUT_DATA_LEN] {
        seal_plaintext(self.record_bytes())
    }

    pub fn from_output_data(data: &[u8]) -> Option<Self> {
        Self::from_record_bytes(open_plaintext(data, SPEND_RECORD_LEN)?)
    }

    fn record_bytes(&self) -> [u8; SPEND_RECORD_LEN] {
        let mut content = [0u8; SPEND_RECORD_LEN];
        content[MEMBER].copy_from_slice(self.member.as_bytes());
        content[VERSION].copy_from_slice(&self.version.to_le_bytes());
        content[WINDOW].copy_from_slice(&self.window.to_le_bytes());
        content[COMMITMENT].copy_from_slice(&self.counters_commitment);
        content[BLINDING].copy_from_slice(&self.blinding);
        content
    }

    fn from_record_bytes(content: &[u8]) -> Option<Self> {
        let content: &[u8; SPEND_RECORD_LEN] = content.try_into().ok()?;
        Some(Self {
            member: Member::from_bytes(content[MEMBER].try_into().ok()?).ok()?,
            version: u64::from_le_bytes(content[VERSION].try_into().ok()?),
            window: u64::from_le_bytes(content[WINDOW].try_into().ok()?),
            counters_commitment: content[COMMITMENT].try_into().ok()?,
            blinding: content[BLINDING].try_into().ok()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendCounters {
    pub salt: [u8; 32],
    pub assets: [[u8; 32]; MAX_VELOCITY_ASSETS],
    pub spent: [u64; MAX_VELOCITY_ASSETS],
}

impl SpendCounters {
    /// Zero salt, the program recomputes the genesis commitment on chain.
    pub const EMPTY: Self = Self {
        salt: [0u8; 32],
        assets: [[0u8; 32]; MAX_VELOCITY_ASSETS],
        spent: [0; MAX_VELOCITY_ASSETS],
    };

    pub fn zero(assets: &[[u8; 32]]) -> Result<Self, RuleTableError> {
        let mut counters = Self::EMPTY;
        counters
            .assets
            .get_mut(..assets.len())
            .ok_or(RuleTableError::TooManyVelocityAssets)?
            .copy_from_slice(assets);
        Ok(counters)
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
        let (slots, _) = bytes[32..].as_chunks_mut::<COUNTER_SLOT_LEN>();
        for ((slot, asset), spent) in slots.iter_mut().zip(&self.assets).zip(self.spent) {
            let (asset_bytes, spent_bytes) = slot.split_at_mut(32);
            asset_bytes.copy_from_slice(asset);
            spent_bytes.copy_from_slice(&spent.to_le_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; SPEND_COUNTERS_LEN] = bytes.try_into().ok()?;
        let mut counters = Self::EMPTY;
        counters.salt = bytes[..32].try_into().ok()?;
        let (slots, _) = bytes[32..].as_chunks::<COUNTER_SLOT_LEN>();
        for ((slot, asset), spent) in slots
            .iter()
            .zip(&mut counters.assets)
            .zip(&mut counters.spent)
        {
            let (asset_bytes, spent_bytes) = slot.split_first_chunk::<32>()?;
            *asset = *asset_bytes;
            *spent = u64::from_le_bytes(spent_bytes.try_into().ok()?);
        }
        Some(counters)
    }

    /// Every slot naming the mint counts, mirroring the circuit.
    pub fn spent(&self, asset: &[u8; 32]) -> u64 {
        self.assets
            .iter()
            .zip(self.spent)
            .filter(|(known, _)| *known == asset)
            .fold(0, |total, (_, spent)| total.saturating_add(spent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(byte: u8) -> Member {
        Member::owner_tag(&[byte; 32]).unwrap()
    }

    #[test]
    fn record_message_tag_is_domain_separated_raw_sha256() {
        assert_eq!(
            hex::encode(spend_record_message_tag(&[7; 32]).unwrap()),
            "87337f4d5068808c2f105da6e07232361fa4683cfe4a17920d01f2542ba46bb2"
        );
        assert_ne!(spend_record_message_tag(&[7; 32]).unwrap(), [7; 32]);
        assert_ne!(
            spend_record_message_tag(&[7; 32]).unwrap(),
            spend_record_message_tag(&[8; 32]).unwrap()
        );
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
        assert_eq!(SpendRecord::from_output_data(&data), Some(record));
        assert_eq!(SpendRecord::from_output_data(&data[..data.len() - 1]), None);
        let mut wrong_scheme = data;
        wrong_scheme[0] = 1;
        assert_eq!(SpendRecord::from_output_data(&wrong_scheme), None);
        let mut wrong_length = data;
        wrong_length[1] ^= 1;
        assert_eq!(SpendRecord::from_output_data(&wrong_length), None);
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
        let mut counters = SpendCounters::zero(&[[1u8; 32], [2u8; 32]]).unwrap();
        counters.salt = [9u8; 32];
        counters.spent[1] = u64::MAX;
        let bytes = counters.to_bytes();
        assert_eq!(SpendCounters::from_bytes(&bytes), Some(counters));
        assert_eq!(SpendCounters::from_bytes(&bytes[1..]), None);
    }

    #[test]
    fn counters_take_at_most_the_circuit_width_of_mints() {
        let eight = [[1u8; 32]; MAX_VELOCITY_ASSETS];
        assert_eq!(SpendCounters::zero(&eight).unwrap().assets, eight);
        let nine = [[1u8; 32]; MAX_VELOCITY_ASSETS + 1];
        assert_eq!(
            SpendCounters::zero(&nine),
            Err(RuleTableError::TooManyVelocityAssets)
        );
        assert_eq!(SpendCounters::zero(&[]), Ok(SpendCounters::EMPTY));
    }

    #[test]
    fn counters_commit_to_their_mints_and_the_salt() {
        let assets = [[1u8; 32], [2u8; 32]];
        let zero = SpendCounters::zero(&assets).unwrap();
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

    #[test]
    fn a_repeated_mint_sums_every_slot_naming_it() {
        let mut counters = SpendCounters::zero(&[[1u8; 32], [1u8; 32], [2u8; 32]]).unwrap();
        counters.spent = [5, 7, 11, 0, 0, 0, 0, 0];
        assert_eq!(counters.spent(&[1u8; 32]), 12);
        assert_eq!(counters.spent(&[2u8; 32]), 11);
        counters.spent[1] = u64::MAX;
        assert_eq!(counters.spent(&[1u8; 32]), u64::MAX);
    }
}
