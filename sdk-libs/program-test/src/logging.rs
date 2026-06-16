use std::{
    fmt::Write,
    sync::atomic::{AtomicUsize, Ordering},
};

use borsh::BorshDeserialize;
use light_instruction_decoder::{
    types::get_program_name, DecodedField, DecodedInstruction, EnhancedInstructionLog,
    EnhancedLoggingConfig, EnhancedTransactionLog, InstructionDecoder, LogVerbosity,
    TransactionFormatter, TransactionStatus,
};
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_instruction::AccountMeta;
use solana_message::{compiled_instruction::CompiledInstruction, Message};
use solana_pubkey::Pubkey;
use zolana_interface::{
    event::{decode_event_payload, ProoflessShieldEvent, ShieldedPoolEvent},
    instruction::{
        tag, BatchUpdateNullifierTreeData, CreateProtocolConfigData, CreateZoneConfigData,
        PauseTreeData, ProoflessShieldIxData, TransactIxData, UpdateProtocolConfigData,
        UpdateZoneConfigData, UpdateZoneConfigOwnerData, ZoneProoflessShieldIxData,
        PUBLIC_AMOUNT_DEPOSIT_SPL,
    },
};

use crate::events::IndexedEvent;

const TEST_LOG_ENV: &str = "ZOLANA_PROGRAM_TEST_LOG";
static TX_COUNTER: AtomicUsize = AtomicUsize::new(1);

pub fn log_transaction(
    shielded_pool_program_id: Pubkey,
    slot: u64,
    message: &Message,
    meta: &TransactionMetadata,
    events: &[IndexedEvent],
) {
    if !log_enabled() {
        return;
    }

    let mut log = transaction_log(shielded_pool_program_id, slot, message, meta);
    log.status = TransactionStatus::Success;
    let mut output = TransactionFormatter::new(&logging_config(shielded_pool_program_id))
        .format(&log, next_tx_number());
    append_indexed_events(&mut output, events);
    eprintln!("{output}");
}

pub fn log_failed_transaction(
    shielded_pool_program_id: Pubkey,
    slot: u64,
    message: &Message,
    err: &FailedTransactionMetadata,
) {
    if !log_enabled() {
        return;
    }

    let mut log = transaction_log(shielded_pool_program_id, slot, message, &err.meta);
    log.status = TransactionStatus::Failed(format!("{:?}", err.err));
    let output = TransactionFormatter::new(&logging_config(shielded_pool_program_id))
        .format(&log, next_tx_number());
    eprintln!("{output}");
}

fn transaction_log(
    shielded_pool_program_id: Pubkey,
    slot: u64,
    message: &Message,
    meta: &TransactionMetadata,
) -> EnhancedTransactionLog {
    let config = logging_config(shielded_pool_program_id);
    let mut log = EnhancedTransactionLog::new(meta.signature, slot);
    log.fee = meta.fee;
    log.compute_used = meta.compute_units_consumed;
    log.instructions = instructions(message, meta, &config);
    log.program_logs_pretty = meta.logs.join("\n");
    log
}

fn next_tx_number() -> usize {
    TX_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn logging_config(shielded_pool_program_id: Pubkey) -> EnhancedLoggingConfig {
    let mut config =
        EnhancedLoggingConfig::default().with_decoders(vec![Box::new(ZolanaInstructionDecoder {
            program_id: shielded_pool_program_id,
        })]);
    config.log_events = true;
    config.show_account_changes = false;
    config.use_colors = false;
    config.verbosity = LogVerbosity::Detailed;
    config
}

fn log_enabled() -> bool {
    let Ok(value) = std::env::var(TEST_LOG_ENV) else {
        return false;
    };
    !matches!(
        value.to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "off"
    )
}

fn instructions(
    message: &Message,
    meta: &TransactionMetadata,
    config: &EnhancedLoggingConfig,
) -> Vec<EnhancedInstructionLog> {
    message
        .instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| {
            let mut log = instruction_log(index, message, instruction, 0, config);
            if let Some(inner_instructions) = meta.inner_instructions.get(index) {
                log.inner_instructions = inner_instructions
                    .iter()
                    .enumerate()
                    .map(|(inner_index, inner)| {
                        instruction_log(inner_index, message, &inner.instruction, 1, config)
                    })
                    .collect();
            }
            log
        })
        .collect()
}

fn instruction_log(
    index: usize,
    message: &Message,
    instruction: &CompiledInstruction,
    depth: usize,
    config: &EnhancedLoggingConfig,
) -> EnhancedInstructionLog {
    let program_id = message
        .account_keys
        .get(instruction.program_id_index as usize)
        .copied()
        .unwrap_or_default();
    let mut log = EnhancedInstructionLog::new(
        index,
        program_id,
        get_program_name(&program_id, config.decoder_registry()),
    );
    log.accounts = account_metas(message, instruction);
    log.data = instruction.data.clone();
    log.depth = depth;
    log.decode(config);
    log
}

fn account_metas(message: &Message, instruction: &CompiledInstruction) -> Vec<AccountMeta> {
    instruction
        .accounts
        .iter()
        .filter_map(|index| {
            let index = *index as usize;
            message
                .account_keys
                .get(index)
                .copied()
                .map(|pubkey| AccountMeta {
                    pubkey,
                    is_signer: message.is_signer(index),
                    is_writable: message.is_maybe_writable(index, None),
                })
        })
        .collect()
}

fn append_indexed_events(output: &mut String, events: &[IndexedEvent]) {
    if events.is_empty() {
        return;
    }

    output.push_str("Indexed events:\n");
    for (index, event) in events.iter().enumerate() {
        output.push_str(&format!("  [{index}] {}\n", event_summary(event)));
    }
}

fn event_summary(event: &IndexedEvent) -> String {
    match &event.decoded {
        Ok(ShieldedPoolEvent::ProoflessShield(event)) => format!(
            "proofless_shield amount={} asset={} view_tag={} utxo_hash={}",
            event.amount,
            pubkey(&event.asset),
            short_hex(&event.view_tag),
            short_hex(&event.utxo_hash)
        ),
        Err(err) => format!("invalid data_len={} error={err:?}", event.payload.len()),
    }
}

struct ZolanaInstructionDecoder {
    program_id: Pubkey,
}

impl InstructionDecoder for ZolanaInstructionDecoder {
    fn program_id(&self) -> Pubkey {
        self.program_id
    }

    fn program_name(&self) -> &'static str {
        "Shielded Pool"
    }

    fn decode(&self, data: &[u8], accounts: &[AccountMeta]) -> Option<DecodedInstruction> {
        let (&tag, payload) = data.split_first()?;
        match tag {
            tag::TRANSACT => TransactIxData::deserialize(payload).ok().and_then(|data| {
                decoded_instruction("transact", transact_fields(data), &["authority", "tree"])
            }),
            tag::PROOFLESS_SHIELD => {
                ProoflessShieldIxData::deserialize(payload)
                    .ok()
                    .and_then(|data| {
                        decoded_instruction(
                            "proofless_shield",
                            proofless_fields(data),
                            proofless_accounts(payload, accounts.len()),
                        )
                    })
            }
            tag::CREATE_SPL_INTERFACE => decode_no_data(
                "create_spl_interface",
                payload,
                &[
                    "authority",
                    "protocol_config",
                    "asset_counter",
                    "registry",
                    "mint",
                    "vault",
                    "cpi_authority",
                    "system_program",
                    "token_program",
                ],
            ),
            tag::CREATE_TREE => decode_no_data(
                "create_tree",
                payload,
                &["authority", "protocol_config", "tree"],
            ),
            tag::CREATE_PROTOCOL_CONFIG => decode::<CreateProtocolConfigData, _>(
                "create_protocol_config",
                payload,
                create_protocol_config_fields,
                &["authority", "protocol_config", "system_program"],
            ),
            tag::UPDATE_PROTOCOL_CONFIG => decode::<UpdateProtocolConfigData, _>(
                "update_protocol_config",
                payload,
                update_protocol_config_fields,
                &["authority", "protocol_config"],
            ),
            tag::PAUSE_TREE => decode(
                "pause_tree",
                payload,
                |data: PauseTreeData| vec![field("paused", data.paused)],
                &["authority", "protocol_config", "tree"],
            ),
            tag::CREATE_ZONE_CONFIG => decode(
                "create_zone_config",
                payload,
                create_zone_config_fields,
                &["payer", "zone_config", "zone_auth", "system_program"],
            ),
            tag::UPDATE_ZONE_CONFIG_OWNER => decode(
                "update_zone_config_owner",
                payload,
                |data: UpdateZoneConfigOwnerData| {
                    vec![field("new_authority", pubkey(&data.new_authority))]
                },
                &["authority", "zone_config"],
            ),
            tag::UPDATE_ZONE_CONFIG => decode(
                "update_zone_config",
                payload,
                |data: UpdateZoneConfigData| {
                    vec![field(
                        "zone_authority_transact_is_enabled",
                        data.zone_authority_transact_is_enabled,
                    )]
                },
                &["authority", "zone_config"],
            ),
            tag::EMIT_EVENT => decode_emit_event(payload),
            tag::ZONE_PROOFLESS_SHIELD => ZoneProoflessShieldIxData::deserialize(payload)
                .ok()
                .and_then(|data| {
                    decoded_instruction(
                        "zone_proofless_shield",
                        zone_proofless_fields(data),
                        &[
                            "tree",
                            "depositor",
                            "zone_auth",
                            "system_program",
                            "cpi_authority",
                            "sol_source",
                            "self_program",
                        ],
                    )
                }),
            tag::BATCH_UPDATE_NULLIFIER_TREE => decode(
                "batch_update_nullifier_tree",
                payload,
                |data: BatchUpdateNullifierTreeData| {
                    vec![field("new_root", short_hex(&data.new_root))]
                },
                &["authority", "protocol_config", "tree"],
            ),
            _ => None,
        }
    }
}

fn decode_emit_event(payload: &[u8]) -> Option<DecodedInstruction> {
    decode_event_payload(payload)
        .ok()
        .and_then(|event| decoded_instruction("emit_event", event_fields(event), &[]))
}

/// Decode an instruction whose payload is just the tag byte (no data fields).
fn decode_no_data(
    name: &'static str,
    payload: &[u8],
    account_names: &[&str],
) -> Option<DecodedInstruction> {
    if !payload.is_empty() {
        return None;
    }
    Some(DecodedInstruction::with_fields_and_accounts(
        name,
        Vec::new(),
        account_names.iter().map(|name| name.to_string()).collect(),
    ))
}

fn decode<T, F>(
    name: &'static str,
    payload: &[u8],
    fields: F,
    account_names: &[&str],
) -> Option<DecodedInstruction>
where
    T: BorshDeserialize,
    F: FnOnce(T) -> Vec<DecodedField>,
{
    T::try_from_slice(payload).ok().map(|data| {
        DecodedInstruction::with_fields_and_accounts(
            name,
            fields(data),
            account_names.iter().map(|name| name.to_string()).collect(),
        )
    })
}

fn decoded_instruction(
    name: &'static str,
    fields: Vec<DecodedField>,
    account_names: &[&str],
) -> Option<DecodedInstruction> {
    Some(DecodedInstruction::with_fields_and_accounts(
        name,
        fields,
        account_names.iter().map(|name| name.to_string()).collect(),
    ))
}

fn proofless_accounts(payload: &[u8], account_count: usize) -> &'static [&'static str] {
    let Ok(data) = ProoflessShieldIxData::deserialize(payload) else {
        return &[];
    };
    if data.public_amount_mode == PUBLIC_AMOUNT_DEPOSIT_SPL {
        &[
            "tree",
            "depositor",
            "cpi_authority",
            "user_token",
            "vault",
            "asset_registry",
            "token_program",
            "self_program",
        ]
    } else if data.cpi_signer.is_some() || account_count == 7 {
        &[
            "tree",
            "depositor",
            "cpi_signer",
            "system_program",
            "cpi_authority",
            "sol_source",
            "self_program",
        ]
    } else {
        &[
            "tree",
            "depositor",
            "system_program",
            "cpi_authority",
            "sol_source",
            "self_program",
        ]
    }
}

fn transact_fields(data: TransactIxData) -> Vec<DecodedField> {
    vec![
        field("expiry_unix_ts", data.expiry_unix_ts),
        field("relayer_fee", data.relayer_fee),
        field("inputs", data.inputs.len()),
        field("public_sol_amount", option_i64(data.public_sol_amount)),
        field("public_spl_amount", option_i64(data.public_spl_amount)),
        field("recipient_utxo_data", data.recipient_utxo_data.len()),
        field("cpi_signer", data.cpi_signer.is_some()),
    ]
}

fn proofless_fields(data: ProoflessShieldIxData) -> Vec<DecodedField> {
    vec![
        field("view_tag", short_hex(&data.view_tag)),
        field("owner_utxo_hash", short_hex(&data.owner_utxo_hash)),
        field("salt", short_hex(&data.salt)),
        field("public_amount_mode", data.public_amount_mode),
        field("public_amount", option_u64(data.public_amount)),
        field("program_data_hash", option_hash(data.program_data_hash)),
        field(
            "program_data_len",
            data.program_data.as_ref().map_or(0, Vec::len),
        ),
        field("cpi_signer", cpi_signer(data.cpi_signer)),
    ]
}

fn zone_proofless_fields(data: ZoneProoflessShieldIxData) -> Vec<DecodedField> {
    vec![
        field("view_tag", short_hex(&data.view_tag)),
        field("owner_utxo_hash", short_hex(&data.owner_utxo_hash)),
        field("salt", short_hex(&data.salt)),
        field("public_amount_mode", data.public_amount_mode),
        field("public_amount", option_u64(data.public_amount)),
        field("cpi_signer", cpi_signer(Some(data.cpi_signer))),
        field("policy_data_hash", option_hash(data.policy_data_hash)),
        field("zone_data_len", data.zone_data.as_ref().map_or(0, Vec::len)),
        field("program_data_hash", option_hash(data.program_data_hash)),
        field(
            "program_data_len",
            data.program_data.as_ref().map_or(0, Vec::len),
        ),
    ]
}

fn proofless_event_fields(data: ProoflessShieldEvent) -> Vec<DecodedField> {
    vec![
        field("amount", data.amount),
        field("asset", pubkey(&data.asset)),
        field("view_tag", short_hex(&data.view_tag)),
        field("utxo_hash", short_hex(&data.utxo_hash)),
        field("owner_utxo_hash", short_hex(&data.owner_utxo_hash)),
        field("zone_program_id", option_pubkey(data.zone_program_id)),
        field("policy_data_hash", option_hash(data.policy_data_hash)),
        field("program_data_hash", option_hash(data.program_data_hash)),
        field(
            "program_data_len",
            data.program_data.as_ref().map_or(0, Vec::len),
        ),
        field("zone_data_len", data.zone_data.as_ref().map_or(0, Vec::len)),
    ]
}

fn event_fields(event: ShieldedPoolEvent) -> Vec<DecodedField> {
    match event {
        ShieldedPoolEvent::ProoflessShield(event) => {
            let mut fields = vec![field("event_kind", "proofless_shield")];
            fields.extend(proofless_event_fields(event));
            fields
        }
    }
}

fn create_protocol_config_fields(data: CreateProtocolConfigData) -> Vec<DecodedField> {
    protocol_config_fields(data.authority, data.merge_authorities.len())
}

fn update_protocol_config_fields(data: UpdateProtocolConfigData) -> Vec<DecodedField> {
    protocol_config_fields(data.authority, data.merge_authorities.len())
}

fn protocol_config_fields(authority: [u8; 32], merge_authorities: usize) -> Vec<DecodedField> {
    vec![
        field("authority", pubkey(&authority)),
        field("merge_authorities", merge_authorities),
    ]
}

fn create_zone_config_fields(data: CreateZoneConfigData) -> Vec<DecodedField> {
    vec![
        field("program_id", pubkey(&data.program_id)),
        field("authority", pubkey(&data.authority)),
        field("zone_auth_bump", data.zone_auth_bump),
        field("zone_config_bump", data.zone_config_bump),
        field(
            "zone_authority_transact_is_enabled",
            data.zone_authority_transact_is_enabled,
        ),
    ]
}

fn field(name: impl Into<String>, value: impl ToString) -> DecodedField {
    DecodedField::new(name, value.to_string())
}

fn pubkey(bytes: &[u8; 32]) -> String {
    Pubkey::new_from_array(*bytes).to_string()
}

fn option_pubkey(value: Option<[u8; 32]>) -> String {
    value
        .map(|bytes| pubkey(&bytes))
        .unwrap_or_else(|| "None".to_string())
}

fn option_hash(value: Option<[u8; 32]>) -> String {
    value
        .map(|bytes| short_hex(&bytes))
        .unwrap_or_else(|| "None".to_string())
}

fn option_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "None".to_string())
}

fn option_i64(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "None".to_string())
}

fn cpi_signer(value: Option<zolana_interface::instruction::CpiSignerData>) -> String {
    value
        .map(|signer| format!("{} bump={}", pubkey(&signer.program_id), signer.bump))
        .unwrap_or_else(|| "None".to_string())
}

fn short_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(10);
    for byte in bytes.iter().take(4) {
        let _ = write!(out, "{byte:02x}");
    }
    if bytes.len() > 4 {
        out.push_str("..");
    }
    out
}

#[cfg(test)]
mod tests {
    use light_instruction_decoder::InstructionDecoder;
    use zolana_interface::{
        instruction::{CpiSignerData, PUBLIC_AMOUNT_DEPOSIT_SOL},
        SHIELDED_POOL_PROGRAM_ID,
    };

    use super::*;

    #[test]
    fn decodes_proofless_shield() {
        let decoder = ZolanaInstructionDecoder {
            program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        };
        let mut data = vec![tag::PROOFLESS_SHIELD];
        data.extend_from_slice(
            &ProoflessShieldIxData {
                view_tag: [1; 32],
                owner_utxo_hash: [2; 32],
                salt: [3; 16],
                public_amount_mode: PUBLIC_AMOUNT_DEPOSIT_SOL,
                public_amount: Some(42),
                program_data_hash: None,
                program_data: None,
                cpi_signer: Some(CpiSignerData {
                    program_id: [4; 32],
                    bump: 255,
                }),
            }
            .serialize()
            .expect("serialize"),
        );

        let decoded = decoder.decode(&data, &[]).expect("decode");

        assert_eq!(decoded.name, "proofless_shield");
        assert_eq!(decoded.account_names[2], "cpi_signer");
        assert!(decoded
            .fields
            .iter()
            .any(|field| field.name == "public_amount" && field.value == "42"));
    }
}
