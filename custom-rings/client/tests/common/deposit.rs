use solana_address::Address;
use zolana_event::{tag, EncryptedRingDepositData};
use zolana_event_parser::{InstructionGroup, ParsedInstruction};
use zolana_interface::{
    instruction::instruction_data::deposit::{
        DepositAssetKind, RingDepositEntry, RingDepositIxData,
    },
    SHIELDED_POOL_PROGRAM_ID,
};

/// Trusted execution metadata, supplied separately from indexed ciphertexts.
pub fn group(ring: Address, audited: bool, deposits: Vec<([u8; 32], Vec<u8>)>) -> InstructionGroup {
    let pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let deposit = RingDepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits: deposits
            .into_iter()
            .map(|(owner_utxo_hash, ciphertext)| RingDepositEntry {
                asset_index: 0,
                view_tag: [0; 32],
                owner_utxo_hash,
                amount: 1,
                ring_data_hash: [0; 32],
                encrypted: EncryptedRingDepositData {
                    tx_viewing_pk: [0; 33],
                    salt: [0; 16],
                    ciphertext,
                },
            })
            .collect(),
    };
    let mut data = vec![tag::RING_DEPOSIT];
    data.extend(deposit.serialize().unwrap());
    let mut outer_data = if audited {
        let mut header = vec![0; 2 + custom_ring_interface::CustomRingProof::SIZE];
        header[0] = custom_ring_interface::tag::AUDITED_DEPOSIT;
        header
    } else {
        Vec::new()
    };
    outer_data.extend_from_slice(&data);
    InstructionGroup {
        outer: ParsedInstruction::new(ring, Vec::new(), outer_data, 1),
        inner: vec![
            ParsedInstruction::new(pool, Vec::new(), data, 2),
            ParsedInstruction::new(pool, Vec::new(), vec![tag::EMIT_EVENT], 3),
        ],
    }
}
