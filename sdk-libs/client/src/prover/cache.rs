use num_bigint::BigUint;
use solana_address::Address;
use zolana_interface::{
    state::cache::{cached_input_fields, empty_cached_input_fields, CACHE_CAPACITY},
    verifying_keys::CacheAccess,
};
use zolana_transaction::{
    instructions::transact::{cache_bound_external_data_hash, cache_write_slots, CacheAccounts},
    ExternalData, SppProofOutputUtxo,
};

use super::{inputs::CacheReadInputs, transact::assembly::TransferInputUtxo};
use crate::error::ClientError;

pub(crate) struct CacheSelection {
    pub access: Option<CacheAccess>,
    pub public_fields: [[u8; 32]; 2],
    pub proof_inputs: CacheReadInputs,
    pub external_data_hash: [u8; 32],
}

struct CacheReads {
    read_bitmap: u64,
    public_fields: [[u8; 32]; 2],
    proof_inputs: CacheReadInputs,
}

impl CacheReadInputs {
    pub fn uncached(public_fields: [[u8; 32]; 2]) -> Self {
        let [tree_id, read_hash_chain] = public_fields;
        Self {
            tree_id: BigUint::from_bytes_be(&tree_id),
            read_hash_chain: BigUint::from_bytes_be(&read_hash_chain),
            ..Self::default()
        }
    }
}

impl CacheSelection {
    pub(crate) fn derive(
        inputs: &[TransferInputUtxo],
        outputs: &[SppProofOutputUtxo],
        accounts: CacheAccounts,
        external_data: &ExternalData,
    ) -> Result<Self, ClientError> {
        let reads = cache_reads(inputs, accounts.read)?;
        let write_slots = cache_write_slots(outputs, accounts.write)?;
        let external_data_hash =
            cache_bound_external_data_hash(external_data, &write_slots, accounts.write)?;
        let access = (reads.read_bitmap != 0 || accounts.write.is_some()).then_some(CacheAccess {
            read_bitmap: reads.read_bitmap,
            write_slots,
        });
        Ok(Self {
            access,
            public_fields: reads.public_fields,
            proof_inputs: reads.proof_inputs,
            external_data_hash,
        })
    }
}

fn cache_reads(
    inputs: &[TransferInputUtxo],
    cache: Option<Address>,
) -> Result<CacheReads, ClientError> {
    let mut slots = [[0u8; 32]; CACHE_CAPACITY];
    let mut read_bitmap = 0u64;
    let mut cache_tree_id = None;
    for (index, input) in inputs.iter().enumerate() {
        let Some(slot) = input.utxo.cache_slot else {
            continue;
        };
        if cache.is_none() {
            return Err(ClientError::CachedInputWithoutReadCache { index });
        }
        let entry = slots
            .get_mut(usize::from(slot))
            .ok_or(ClientError::CacheReadSlotOutOfRange { index, slot })?;
        if read_bitmap >> slot & 1 == 1 {
            return Err(ClientError::DuplicateCacheReadSlot { index, slot });
        }
        let tree_id = *cache_tree_id.get_or_insert(input.utxo.tree_id);
        if input.utxo.tree_id != tree_id {
            return Err(ClientError::CacheReadTreeMismatch {
                index,
                tree_id: input.utxo.tree_id,
                cache_tree_id: tree_id,
            });
        }
        *entry = input.utxo.utxo_hash;
        read_bitmap |= 1 << slot;
    }
    let Some(tree_id) = cache_tree_id else {
        if cache.is_some() {
            return Err(ClientError::UnusedReadCache);
        }
        let public_fields = empty_cached_input_fields(inputs.len())?;
        return Ok(CacheReads {
            read_bitmap,
            public_fields,
            proof_inputs: CacheReadInputs::uncached(public_fields),
        });
    };
    let public_fields = cached_input_fields(read_bitmap, tree_id, &slots, inputs.len())?;
    let mut read_hashes: Vec<BigUint> = slots
        .iter()
        .enumerate()
        .filter(|(slot, _)| read_bitmap >> slot & 1 == 1)
        .map(|(_, hash)| BigUint::from_bytes_be(hash))
        .collect();
    read_hashes.resize(inputs.len(), BigUint::ZERO);
    let [tree_field, chain] = public_fields;
    Ok(CacheReads {
        read_bitmap,
        public_fields,
        proof_inputs: CacheReadInputs {
            tree_id: BigUint::from_bytes_be(&tree_field),
            read_hash_chain: BigUint::from_bytes_be(&chain),
            read_hashes,
            is_cached: inputs
                .iter()
                .map(|input| input.utxo.cache_slot.is_some())
                .collect(),
            read_index: inputs
                .iter()
                .map(|input| {
                    input.utxo.cache_slot.map_or(0, |slot| {
                        (read_bitmap & ((1u64 << slot) - 1)).count_ones() as usize
                    })
                })
                .collect(),
        },
    })
}
