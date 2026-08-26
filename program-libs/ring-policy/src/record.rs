use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::hash_bytes, Hasher, HasherError, Poseidon,
};
use zolana_interface::{ADDRESS_DOMAIN, SOL_ASSET_FIELD, UTXO_DOMAIN};

use crate::{field_u16, field_u64, field_u8, Member, POLICY_ADDRESS_DOMAIN, POLICY_RECORD_DOMAIN};

/// The on-chain discriminant of a record list, never `0` (the circuit reserves it as the inline-asset sentinel).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    Allow = 1,
    Block = 2,
    Frozen = 3,
    RingViewing = 4,
    Recovery = 5,
    Reader = 6,
    Approval = 7,
    Escrow = 8,
}

/// Who may mutate a record list, the sole authorization axis the program gates on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holder {
    Authority,
    Member,
}

impl RecordKind {
    /// The single source of truth the program and every `List` impl read.
    /// Exhaustive on purpose, a new kind must declare its holder to compile.
    pub const fn holder(self) -> Holder {
        match self {
            Self::RingViewing | Self::Recovery | Self::Escrow => Holder::Member,
            Self::Allow | Self::Block | Self::Frozen | Self::Reader | Self::Approval => {
                Holder::Authority
            }
        }
    }
}

impl TryFrom<u8> for RecordKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        Ok(match value {
            1 => Self::Allow,
            2 => Self::Block,
            3 => Self::Frozen,
            4 => Self::RingViewing,
            5 => Self::Recovery,
            6 => Self::Reader,
            7 => Self::Approval,
            8 => Self::Escrow,
            _ => return Err(()),
        })
    }
}

pub const POLICY_RECORDS_PDA_SEED: &[u8] = b"policy_records";

pub const RECORD_PAYLOAD_LEN: usize = 74;
/// The plaintext output-data envelope, tag byte and `u32` length before the
/// payload.
pub const RECORD_OUTPUT_DATA_LEN: usize = 5 + RECORD_PAYLOAD_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordState {
    Active = 1,
    Cleared = 2,
}

impl TryFrom<u8> for RecordState {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        Ok(match value {
            1 => Self::Active,
            2 => Self::Cleared,
            _ => return Err(()),
        })
    }
}

/// The zero nullifier secret makes every record nullifier publicly computable,
/// spending still needs the PDA signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordsOwner {
    pub owner_hash: [u8; 32],
}

impl RecordsOwner {
    pub fn new(pda: &[u8; 32]) -> Result<Self, HasherError> {
        let owner_pk_field = hash_bytes(pda)?;
        let nullifier_pk = Poseidon::hashv(&[&[0u8; 32]])?;
        let owner_hash = Poseidon::hashv(&[&owner_pk_field, &nullifier_pk])?;
        Ok(Self { owner_hash })
    }

    /// The address slot commitment, its blinding is the record seed.
    pub fn address_utxo_hash(&self, seed: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        let zero = [0u8; 32];
        let ring_hash = Poseidon::hashv(&[&zero, &zero])?;
        let owner_utxo_hash = Poseidon::hashv(&[&self.owner_hash, seed])?;
        Poseidon::hashv(&[
            &field_u16(ADDRESS_DOMAIN),
            &zero,
            &zero,
            &zero,
            &ring_hash,
            &owner_utxo_hash,
        ])
    }

    /// Deterministic, the nullifier tree admits one record lineage per
    /// `(kind, member)`.
    pub fn address(&self, kind: RecordKind, member: &Member) -> Result<[u8; 32], HasherError> {
        let seed = record_seed(kind, member)?;
        record_nullifier(&self.address_utxo_hash(&seed)?, &seed)
    }
}

pub fn record_seed(kind: RecordKind, member: &Member) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[
        &POLICY_ADDRESS_DOMAIN,
        &field_u8(kind as u8),
        member.as_bytes(),
    ])
}

/// The blinding is the version, a re-added member never repeats a commitment
/// or a nullifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub kind: RecordKind,
    pub member: Member,
    pub state: RecordState,
    pub version: u64,
    pub payload_hash: [u8; 32],
}

impl Record {
    pub fn data_hash(&self, address: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &POLICY_RECORD_DOMAIN,
            address,
            &field_u8(self.kind as u8),
            self.member.as_bytes(),
            &field_u8(self.state as u8),
            &field_u64(self.version),
            &self.payload_hash,
        ])
    }

    pub fn blinding(&self) -> [u8; 32] {
        field_u64(self.version)
    }

    /// Takes the payload of [`Record::to_output_data`], without its envelope.
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        let payload: &[u8; RECORD_PAYLOAD_LEN] = payload.try_into().ok()?;
        Some(Self {
            kind: RecordKind::try_from(payload[0]).ok()?,
            member: Member::from_bytes(payload[1..33].try_into().ok()?).ok()?,
            state: RecordState::try_from(payload[33]).ok()?,
            version: u64::from_le_bytes(payload[34..42].try_into().ok()?),
            payload_hash: payload[42..74].try_into().ok()?,
        })
    }

    /// The published plaintext payload, discovery re-derives `data_hash` from
    /// it and compares against the on-chain leaf before trusting it.
    pub fn to_output_data(&self) -> [u8; RECORD_OUTPUT_DATA_LEN] {
        let mut payload = [0u8; RECORD_OUTPUT_DATA_LEN];
        payload[1..5].copy_from_slice(&(RECORD_PAYLOAD_LEN as u32).to_le_bytes());
        payload[5] = self.kind as u8;
        payload[6..38].copy_from_slice(self.member.as_bytes());
        payload[38] = self.state as u8;
        payload[39..47].copy_from_slice(&self.version.to_le_bytes());
        payload[47..79].copy_from_slice(&self.payload_hash);
        payload
    }

    pub fn utxo_hash(
        &self,
        owner: &RecordsOwner,
        address: &[u8; 32],
    ) -> Result<[u8; 32], HasherError> {
        let zero = [0u8; 32];
        let ring_hash = Poseidon::hashv(&[&zero, &zero])?;
        let owner_utxo_hash = Poseidon::hashv(&[&owner.owner_hash, &self.blinding()])?;
        Poseidon::hashv(&[
            &field_u16(UTXO_DOMAIN),
            &SOL_ASSET_FIELD,
            &zero,
            &self.data_hash(address)?,
            &ring_hash,
            &owner_utxo_hash,
        ])
    }
}

pub fn record_nullifier(
    utxo_hash: &[u8; 32],
    blinding: &[u8; 32],
) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[utxo_hash, blinding, &[0u8; 32]])
}

/// `private_tx_hash` of a record mutation, one input slot and one output slot.
pub fn mutation_private_tx_hash(
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    address_hash: [u8; 32],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32], HasherError> {
    let input_chain = create_hash_chain_from_slice(&[input_hash])?;
    let output_chain = create_hash_chain_from_slice(&[output_hash])?;
    let address_chain = create_hash_chain_from_slice(&[address_hash])?;
    Poseidon::hashv(&[
        &input_chain,
        &output_chain,
        &address_chain,
        external_data_hash,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> RecordsOwner {
        RecordsOwner::new(&[11u8; 32]).unwrap()
    }

    fn member(byte: u8) -> Member {
        Member::owner_tag(&[byte; 32]).unwrap()
    }

    #[test]
    fn the_address_is_deterministic_in_kind_and_member() {
        let owner = owner();
        let a = owner.address(RecordKind::Block, &member(1)).unwrap();
        assert_eq!(a, owner.address(RecordKind::Block, &member(1)).unwrap());
        assert_ne!(a, owner.address(RecordKind::Frozen, &member(1)).unwrap());
        assert_ne!(a, owner.address(RecordKind::Block, &member(2)).unwrap());
        assert_ne!(
            a,
            RecordsOwner::new(&[12u8; 32])
                .unwrap()
                .address(RecordKind::Block, &member(1))
                .unwrap()
        );
    }

    #[test]
    fn state_and_version_move_the_commitment_but_not_the_address() {
        let owner = owner();
        let record = Record {
            kind: RecordKind::Block,
            member: member(1),
            state: RecordState::Active,
            version: 0,
            payload_hash: [0u8; 32],
        };
        let address = owner.address(record.kind, &record.member).unwrap();
        let active = record.utxo_hash(&owner, &address).unwrap();
        let cleared = Record {
            state: RecordState::Cleared,
            version: 1,
            ..record
        };
        assert_ne!(active, cleared.utxo_hash(&owner, &address).unwrap());
        assert_eq!(
            address,
            owner.address(cleared.kind, &cleared.member).unwrap()
        );
    }

    #[test]
    fn the_payload_round_trips_through_the_published_envelope() {
        let record = Record {
            kind: RecordKind::Frozen,
            member: member(5),
            state: RecordState::Cleared,
            version: 7,
            payload_hash: [4u8; 32],
        };
        let encoded = record.to_output_data();
        assert_eq!(Record::from_payload(&encoded[5..]), Some(record));
        assert_eq!(Record::from_payload(&encoded), None);
    }

    #[test]
    fn version_uniqueness_separates_nullifiers_of_equal_states() {
        let owner = owner();
        let record = Record {
            kind: RecordKind::Allow,
            member: member(3),
            state: RecordState::Active,
            version: 0,
            payload_hash: [0u8; 32],
        };
        let address = owner.address(record.kind, &record.member).unwrap();
        let re_added = Record {
            version: 2,
            ..record
        };
        let first = record.utxo_hash(&owner, &address).unwrap();
        let second = re_added.utxo_hash(&owner, &address).unwrap();
        assert_ne!(
            record_nullifier(&first, &record.blinding()).unwrap(),
            record_nullifier(&second, &re_added.blinding()).unwrap()
        );
    }
}
