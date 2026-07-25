use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::{MessageData, OutputDataEncoding};
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_keypair::{hash::poseidon, random_blinding, P256Pubkey, ShieldedAddress};

use super::external_data::ExternalData;
use crate::{
    data::{Data, DataRecord},
    error::TransactionError,
    utxo::{Blinding, ProofInputUtxo, Utxo},
};

/// Canonical ordering key for data records: `ZoneData` < `UtxoData` < `Memo`,
/// matching `Data::validate`.
fn canonical_data_order(record: &DataRecord) -> u8 {
    match record {
        DataRecord::ZoneData(_) => 0,
        DataRecord::UtxoData(_) => 1,
        DataRecord::Memo(_) => 2,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputUtxo {
    pub utxo: Utxo,
    pub nullifier_pk: [u8; 32],
    pub zone_data_hash: Option<[u8; 32]>,
    pub data_hash: Option<[u8; 32]>,
}

impl InputUtxo {
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        self.utxo.hash(
            &self.nullifier_pk,
            &self.data_hash.unwrap_or_default(),
            &self.zone_data_hash.unwrap_or_default(),
        )
    }

    pub fn is_dummy(&self) -> bool {
        self.utxo.owner.is_zero()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SppProofOutputUtxo {
    pub asset: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub zone_program_id: Option<Address>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub data_hash: Option<[u8; 32]>,
    pub owner_address: Option<ShieldedAddress>,
    pub owner_tag: Option<[u8; 32]>,
    pub data: Data,
}

impl SppProofOutputUtxo {
    pub fn new(
        asset: Address,
        amount: u64,
        owner_address: ShieldedAddress,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            asset,
            amount,
            blinding: random_blinding(),
            owner_tag: Some(owner_address.signing_pubkey.confidential_view_tag()?),
            owner_address: Some(owner_address),
            ..Default::default()
        })
    }

    pub fn with_zone_data(
        mut self,
        zone_program_id: Address,
        zone_data: Vec<u8>,
        zone_data_hash: [u8; 32],
    ) -> Self {
        self.zone_data_hash = Some(zone_data_hash);
        self.zone_program_id = Some(zone_program_id);
        self.set_data_record(DataRecord::ZoneData(zone_data));
        self
    }

    pub fn with_zone_program_id(mut self, zone_program_id: Address) -> Self {
        self.zone_program_id = Some(zone_program_id);
        self
    }

    /// Bind an output to policy-zone state when only its commitment hash belongs
    /// in the merge witness. The zone is responsible for making the corresponding
    /// preimage available to the owner according to its policy protocol.
    pub fn with_zone_data_hash(
        mut self,
        zone_program_id: Address,
        zone_data_hash: [u8; 32],
    ) -> Self {
        self.zone_program_id = Some(zone_program_id);
        self.zone_data_hash = Some(zone_data_hash);
        self
    }

    pub fn with_utxo_data(mut self, utxo_data: Vec<u8>, data_hash: [u8; 32]) -> Self {
        self.data_hash = Some(data_hash);
        self.set_data_record(DataRecord::UtxoData(utxo_data));
        self
    }

    /// Attach a free-form memo to the output. The memo is encrypted into the
    /// recipient's note but not bound by the commitment, so unlike
    /// `with_utxo_data`/`with_zone_data` it sets no `data_hash`.
    pub fn with_memo(mut self, memo: Vec<u8>) -> Self {
        self.set_data_record(DataRecord::Memo(memo));
        self
    }

    fn set_data_record(&mut self, record: DataRecord) {
        let order = canonical_data_order(&record);
        self.data
            .records
            .retain(|existing| canonical_data_order(existing) != order);
        self.data.records.push(record);
        self.data.records.sort_by_key(canonical_data_order);
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], TransactionError> {
        match &self.owner_address {
            Some(address) => Ok(address.owner_hash()?),
            None => Ok([0u8; 32]),
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        ProofInputUtxo::try_from(self)?.hash()
    }

    pub fn is_dummy(&self) -> bool {
        self.owner_address.is_none()
    }
}

impl TryFrom<&SppProofOutputUtxo> for ProofInputUtxo {
    type Error = TransactionError;

    fn try_from(output: &SppProofOutputUtxo) -> Result<Self, Self::Error> {
        ProofInputUtxo::new(
            output.owner_hash()?,
            &output.asset,
            output.amount,
            &output.blinding,
        )?
        .with_data_hash(output.data_hash.unwrap_or_default())
        .with_zone(
            output.zone_data_hash.unwrap_or_default(),
            &output.zone_program_id,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedTransaction {
    pub inputs: Vec<InputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub external_data: ExternalData,
}

impl EncryptedTransaction {
    /// An unused slot contributes a zero hash, matching the circuit's
    /// `private_tx_hash` and [`SppProofInputs::message_hash`](crate::instructions::transact::SppProofInputs::message_hash).
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let input_hashes = self
            .inputs
            .iter()
            .map(|input| {
                if input.is_dummy() {
                    Ok([0u8; 32])
                } else {
                    input.hash()
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output_hashes = self
            .outputs
            .iter()
            .map(|output| {
                if output.is_dummy() {
                    Ok([0u8; 32])
                } else {
                    output.hash()
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        PrivateTxHash::new(&input_hashes, &output_hashes, &self.external_data.hash()?).hash()
    }
}

pub struct PrivateTxHash<'a> {
    pub input_hashes: &'a [[u8; 32]],
    pub output_hashes: &'a [[u8; 32]],
    pub address_hashes: Option<&'a [[u8; 32]]>,
    pub external_data_hash: &'a [u8; 32],
}

impl<'a> PrivateTxHash<'a> {
    pub fn new(
        input_hashes: &'a [[u8; 32]],
        output_hashes: &'a [[u8; 32]],
        external_data_hash: &'a [u8; 32],
    ) -> Self {
        Self {
            input_hashes,
            output_hashes,
            address_hashes: None,
            external_data_hash,
        }
    }

    /// The circuit reads one address hash per input slot, so a supplied set of a
    /// different length would silently shift the address chain.
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let input_chain = create_hash_chain_from_slice(self.input_hashes)?;
        let output_chain = create_hash_chain_from_slice(self.output_hashes)?;
        let address_chain = match self.address_hashes {
            Some(address_hashes) if address_hashes.len() != self.input_hashes.len() => {
                return Err(TransactionError::AddressHashCountMismatch {
                    expected: self.input_hashes.len(),
                    actual: address_hashes.len(),
                })
            }
            Some(address_hashes) => create_hash_chain_from_slice(address_hashes)?,
            None => create_hash_chain_from_slice(&vec![[0u8; 32]; self.input_hashes.len()])?,
        };
        Ok(poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            self.external_data_hash,
        ])?)
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::PublicKey;

    use super::*;

    fn empty_external_data() -> ExternalData {
        ExternalData::new([0u8; 33], [0u8; 16], Vec::new(), Vec::new(), Vec::new())
    }

    fn dummy_input() -> InputUtxo {
        InputUtxo {
            utxo: Utxo {
                owner: PublicKey::zeroed(),
                asset: Address::default(),
                amount: 0,
                blinding: [4u8; 31],
                zone_program_id: None,
                data: Data::default(),
            },
            nullifier_pk: [0u8; 32],
            zone_data_hash: None,
            data_hash: None,
        }
    }

    #[test]
    fn address_hashes_must_pair_with_the_input_slots() {
        let inputs = [[1u8; 32], [2u8; 32]];
        let outputs = [[3u8; 32]];
        let addresses = [[4u8; 32]];
        let external_data_hash = [5u8; 32];

        let mut private_tx = PrivateTxHash::new(&inputs, &outputs, &external_data_hash);
        private_tx.address_hashes = Some(&addresses);

        assert_eq!(
            private_tx.hash(),
            Err(TransactionError::AddressHashCountMismatch {
                expected: 2,
                actual: 1,
            })
        );
    }

    /// Padding slots must drop out of `private_tx_hash` exactly as the circuit
    /// drops them, so the same transaction hashes the same on both paths.
    #[test]
    fn dummy_slots_contribute_zero_hashes() {
        let external_data = empty_external_data();
        let external_data_hash = external_data.hash().expect("external data hash");
        let transaction = EncryptedTransaction {
            inputs: vec![dummy_input()],
            outputs: vec![SppProofOutputUtxo::default()],
            external_data,
        };

        let expected = PrivateTxHash::new(&[[0u8; 32]], &[[0u8; 32]], &external_data_hash)
            .hash()
            .expect("private tx hash");

        assert_eq!(transaction.hash().expect("transaction hash"), expected);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputContext {
    pub hash: [u8; 32],
    pub tree: Address,
    pub leaf_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSlot {
    pub view_tag: [u8; 32],
    pub output_context: OutputContext,
    pub payload: Vec<u8>,
}

impl OutputSlot {
    pub fn output_data(&self) -> Option<OutputDataEncoding> {
        OutputDataEncoding::try_from_slice(&self.payload).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedTransaction {
    pub slot: u64,
    pub tx_signature: solana_signature::Signature,
    pub tx_viewing_pk: Option<P256Pubkey>,
    pub salt: Option<[u8; 16]>,
    pub output_slots: Vec<OutputSlot>,
    pub messages: Vec<MessageData>,
    pub nullifiers: Vec<[u8; 32]>,
    pub proofless: bool,
}
