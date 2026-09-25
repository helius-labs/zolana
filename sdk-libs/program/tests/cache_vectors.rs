use serde_json::{json, Value};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::{
    instruction::{
        CacheAccess, CacheWrite, CircuitId, CreateCacheData, InputUtxo, OwnerTag, TransactIxData,
        TransactOutput, TransactProof, TreeContext,
    },
    pda,
    state::cache::{
        bind_cache_write, cached_input_fields, empty_cached_input_fields, CacheAccount,
        CACHE_CAPACITY,
    },
    verifying_keys::MAX_CACHE_WRITES,
};
use zolana_program::instruction::{CloseCache, CreateCache};

const CACHE_VECTORS_JSON: &str = include_str!("../../../test-vectors/cache.json");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn field(seed: u8) -> [u8; 32] {
    let mut bytes = [seed; 32];
    bytes[0] = 0;
    bytes
}

fn address(seed: u8) -> Address {
    Address::new_from_array([seed; 32])
}

fn account_metas(accounts: &[AccountMeta]) -> Value {
    Value::Array(
        accounts
            .iter()
            .map(|meta| {
                json!({
                    "address": meta.pubkey.to_string(),
                    "signer": meta.is_signer,
                    "writable": meta.is_writable,
                })
            })
            .collect(),
    )
}

fn instruction_vector(instruction: &Instruction) -> Value {
    json!({
        "data": hex(&instruction.data),
        "accounts": account_metas(&instruction.accounts),
    })
}

fn create_cache_vector() -> Value {
    let payer = address(0x11);
    let data = CreateCacheData {
        write_authority: address(0x22),
        nonce: 0x0102_0304_0506_0708,
        tree_id: 0x0203,
        expires_at: 1_800_000_000,
    };
    let builder = CreateCache { payer, data };
    let (cache, bump) = pda::cache(&payer, data.nonce);
    json!({
        "payer": payer.to_string(),
        "writeAuthority": address(0x22).to_string(),
        "nonce": data.nonce.to_string(),
        "treeId": data.tree_id,
        "expiresAt": data.expires_at.to_string(),
        "cache": cache.to_string(),
        "bump": bump,
        "instruction": instruction_vector(&builder.instruction()),
    })
}

fn close_cache_vectors() -> Value {
    let cache = address(0x33);
    let rent_recipient = address(0x44);
    let writer = address(0x55);
    Value::Array(
        [Some(writer), None]
            .into_iter()
            .map(|writer| {
                let instruction = CloseCache {
                    cache,
                    rent_recipient,
                    writer,
                }
                .instruction();
                json!({
                    "cache": cache.to_string(),
                    "rentRecipient": rent_recipient.to_string(),
                    "writer": writer.map(|writer| writer.to_string()),
                    "instruction": instruction_vector(&instruction),
                })
            })
            .collect(),
    )
}

fn cache_pda_vectors() -> Value {
    Value::Array(
        [
            (address(0x11), 0u64),
            (address(0x11), 1),
            (address(0x11), u64::MAX),
            (address(0x66), 0),
        ]
        .into_iter()
        .map(|(rent_sponsor, nonce)| {
            let (cache, bump) = pda::cache(&rent_sponsor, nonce);
            json!({
                "rentSponsor": rent_sponsor.to_string(),
                "nonce": nonce.to_string(),
                "address": cache.to_string(),
                "bump": bump,
            })
        })
        .collect(),
    )
}

fn cached_input_field_vectors() -> Value {
    let mut slots = [[0u8; 32]; CACHE_CAPACITY];
    for (slot, hash) in (1..=CACHE_CAPACITY as u8).zip(slots.iter_mut()) {
        *hash = field(slot);
    }
    let every_slot = (1u64 << CACHE_CAPACITY) - 1;
    Value::Array(
        [
            ("no slot read", 0u64, 7u16, 2usize),
            ("one slot for one input", 0b1, 0, 1),
            ("first and third slot for three inputs", 0b101, 3, 3),
            ("a high slot for two inputs", 1 << 30, 1, 2),
            (
                "two scattered slots for five inputs",
                1 << 20 | 1 << 2,
                4,
                5,
            ),
            (
                "last slot for the widest shape",
                1 << (CACHE_CAPACITY - 1),
                2,
                CACHE_CAPACITY,
            ),
            (
                "every slot for the widest shape",
                every_slot,
                u16::MAX,
                CACHE_CAPACITY,
            ),
        ]
        .into_iter()
        .map(|(name, read_bitmap, tree_id, input_count)| {
            let fields =
                cached_input_fields(read_bitmap, tree_id, &slots, input_count).expect("fields");
            json!({
                "name": name,
                "readBitmap": read_bitmap.to_string(),
                "treeId": tree_id,
                "inputCount": input_count,
                "slots": slots.iter().map(|hash| hex(hash)).collect::<Vec<_>>(),
                "fields": fields.iter().map(|field| hex(field)).collect::<Vec<_>>(),
            })
        })
        .collect(),
    )
}

fn empty_cached_input_field_vectors() -> Value {
    Value::Array(
        [1usize, 2, 3, 4, 5, 8, CACHE_CAPACITY]
            .into_iter()
            .map(|input_count| {
                let fields = empty_cached_input_fields(input_count).expect("fields");
                json!({
                    "inputCount": input_count,
                    "fields": fields.iter().map(|field| hex(field)).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn writes(pairs: &[(u8, u8)]) -> [CacheWrite; MAX_CACHE_WRITES] {
    let mut out = CacheAccess::NO_WRITES;
    for (entry, (output, slot)) in out.iter_mut().zip(pairs) {
        *entry = CacheWrite {
            output: *output,
            slot: *slot,
        };
    }
    out
}

fn write_slots_json(write_slots: &[CacheWrite; MAX_CACHE_WRITES]) -> Value {
    Value::Array(
        write_slots
            .iter()
            .map(|entry| json!([entry.output, entry.slot]))
            .collect(),
    )
}

fn cache_write_binding_vectors() -> Value {
    Value::Array(
        [
            (field(0x0a), address(0x0b), writes(&[(0, 0), (1, 1)])),
            (
                field(0x0c),
                address(0x0d),
                writes(&[(1, CACHE_CAPACITY as u8 - 1), (0, 2)]),
            ),
        ]
        .into_iter()
        .map(|(external_data_hash, cache, write_slots)| {
            let bound =
                bind_cache_write(external_data_hash, Some((&cache.to_bytes(), &write_slots)))
                    .expect("binding");
            json!({
                "externalDataHash": hex(&external_data_hash),
                "cache": cache.to_string(),
                "writeSlots": write_slots_json(&write_slots),
                "bound": hex(&bound),
            })
        })
        .collect(),
    )
}

fn transact_data(circuit: CircuitId) -> TransactIxData {
    let (n_inputs, n_outputs, _) = circuit.shape();
    TransactIxData {
        expiry_unix_ts: 77,
        tx_viewing_pk: [3; 33],
        salt: [4; 16],
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: (0..n_outputs)
            .map(|index| TransactOutput {
                utxo_hash: field(0x50 + index),
                owner_tag: OwnerTag::Inline(field(0x60 + index)),
                data: None,
            })
            .collect(),
        messages: Vec::new(),
        private_tx_hash: field(5),
        circuit,
        proof: TransactProof {
            a: [6; 32],
            b: [7; 128],
            c: [8; 32],
        },
        inputs: (0..n_inputs)
            .map(|index| InputUtxo {
                nullifier_hash: field(0x10 + index),
                tree_index: 0,
            })
            .collect(),
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 9,
            nullifier_tree_root_index: 10,
        }],
    }
}

fn circuit_json(circuit: CircuitId) -> Value {
    let (inputs, outputs, public_asset_slots) = circuit.shape();
    let kind = match circuit {
        CircuitId::ConfidentialEddsa(..) => "confidentialEddsa",
        CircuitId::RingEddsa(..) => "ringEddsa",
        CircuitId::ConfidentialEddsaCached(..) => "confidentialEddsaCached",
        CircuitId::RingEddsaCached(..) => "ringEddsaCached",
        _ => panic!("the shared vectors cover the EdDSA rails"),
    };
    let mut value = json!({
        "kind": kind,
        "inputs": inputs,
        "outputs": outputs,
        "publicAssetSlots": public_asset_slots,
    });
    if let Some(access) = circuit.cache_access() {
        value["readBitmap"] = json!(access.read_bitmap.to_string());
        value["writeSlots"] = write_slots_json(&access.write_slots);
    }
    value
}

fn transact_circuit_vectors() -> Value {
    Value::Array(
        [
            CircuitId::ConfidentialEddsa(2, 3, 3),
            CircuitId::ConfidentialEddsaCached(
                2,
                3,
                3,
                CacheAccess {
                    read_bitmap: 1 << 20,
                    write_slots: CacheAccess::NO_WRITES,
                },
            ),
            CircuitId::ConfidentialEddsaCached(
                1,
                2,
                3,
                CacheAccess {
                    read_bitmap: 0,
                    write_slots: writes(&[(1, 35), (0, 34)]),
                },
            ),
            CircuitId::RingEddsaCached(
                2,
                2,
                3,
                CacheAccess {
                    read_bitmap: 0b11,
                    write_slots: writes(&[(0, 2), (1, 3)]),
                },
            ),
        ]
        .into_iter()
        .map(|circuit| {
            let data = transact_data(circuit)
                .serialize()
                .expect("serialize transact");
            json!({
                "circuit": circuit_json(circuit),
                "data": hex(&data),
            })
        })
        .collect(),
    )
}

fn cache_account_vector() -> Value {
    let mut utxo_hashes = [[0u8; 32]; CACHE_CAPACITY];
    let filled = [(0usize, field(0x70)), (5, field(0x71)), (35, field(0x72))];
    for (slot, hash) in filled {
        *utxo_hashes.get_mut(slot).expect("slot") = hash;
    }
    let account = CacheAccount {
        discriminator: zolana_interface::state::discriminator::CACHE,
        bump: 254,
        tree_id: 0x0203u16.to_le_bytes(),
        expires_at: 1_800_000_000i64.to_le_bytes(),
        rent_sponsor: address(0x11),
        write_authority: address(0x22),
        utxo_hashes,
    };
    let bytes = bytemuck::bytes_of(&account);
    let header_len = CacheAccount::SIZE - 32 * CACHE_CAPACITY;
    assert_eq!(
        bytes.get(header_len..).expect("slots"),
        account.utxo_hashes.concat().as_slice()
    );
    json!({
        "header": hex(bytes.get(..header_len).expect("header")),
        "utxoHashes": account.utxo_hashes.iter().map(|hash| hex(hash)).collect::<Vec<_>>(),
        "bump": account.bump,
        "treeId": 0x0203,
        "expiresAt": account.expiry_unix_ts().to_string(),
        "rentSponsor": address(0x11).to_string(),
        "writeAuthority": address(0x22).to_string(),
    })
}

fn compute_cache_vectors() -> Value {
    json!({
        "description": "Cache encodings the TypeScript SDK must reproduce: the create and close cache instructions, the cache PDA, the cache account layout, the cached input fields every owner-signed transfer publishes, the write binding of the transact external data hash, and the cached circuit selectors in transact instruction data. Regenerate with `cargo test -p zolana-interface --features solana --test cache_vectors print_cache_vectors -- --ignored --nocapture`.",
        "createCache": create_cache_vector(),
        "closeCache": close_cache_vectors(),
        "cachePdas": cache_pda_vectors(),
        "cacheAccount": cache_account_vector(),
        "cachedInputFields": cached_input_field_vectors(),
        "emptyCachedInputFields": empty_cached_input_field_vectors(),
        "cacheWriteBindings": cache_write_binding_vectors(),
        "transactCircuits": transact_circuit_vectors(),
    })
}

#[test]
fn cache_encodings_match_the_shared_vectors() {
    let committed: Value = serde_json::from_str(CACHE_VECTORS_JSON).expect("shared cache vectors");
    assert_eq!(committed, compute_cache_vectors());
}

#[test]
#[ignore = "regenerates test-vectors/cache.json; run with --nocapture and commit the output"]
fn print_cache_vectors() {
    println!(
        "{}",
        serde_json::to_string_pretty(&compute_cache_vectors()).expect("json")
    );
}
