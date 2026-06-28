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
use zolana_event::{decode_event_payload, proofless_output, ProoflessOutput};
use zolana_interface::{
    event::GeneralEvent,
    instruction::{
        tag, BatchUpdateNullifierTreeData, CreateProtocolConfigData, CreateZoneConfigData,
        DepositIxData, PauseTreeData, TransactIxData, UpdateProtocolConfigData,
        UpdateZoneConfigData, UpdateZoneConfigOwnerData, ZoneDepositIxData,
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
        Ok(event) => match proofless_output(event) {
            Ok(output) => {
                let slot = event.outputs.first();
                format!(
                    "deposit amount={} asset={} view_tag={} utxo_hash={} leaf_index={}",
                    output.amount,
                    pubkey(&output.asset),
                    slot.map_or_else(|| "?".to_string(), |s| short_hex(&s.view_tag)),
                    slot.map_or_else(|| "?".to_string(), |s| short_hex(&s.utxo_hash)),
                    event.first_output_leaf_index
                )
            }
            Err(_) => format!(
                "general_event inputs={} outputs={} first_output_leaf_index={}",
                event.inputs.len(),
                event.outputs.len(),
                event.first_output_leaf_index
            ),
        },
        Err(err) => format!("invalid data_len={} error={err:?}", event.payload.len()),
    }
}

/// Decodes shielded-pool instructions (and the indexer's `emit_event` payload)
/// into named fields and account names for the enhanced transaction logger. It is
/// also exported so tests can decode a single instruction they built.
pub struct ZolanaInstructionDecoder {
    pub program_id: Pubkey,
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
            tag::TRANSACT => TransactIxData::deserialize(payload).ok().map(|data| {
                let account_names = transact_accounts(&data, accounts.len());
                DecodedInstruction::with_fields_and_accounts(
                    "transact",
                    transact_fields(data),
                    account_names,
                )
            }),
            tag::DEPOSIT => DepositIxData::deserialize(payload).ok().and_then(|data| {
                decoded_instruction(
                    "deposit",
                    proofless_fields(data),
                    proofless_accounts(payload, accounts.len()),
                )
            }),
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
                    vec![field(
                        "new_authority",
                        pubkey(data.new_authority.as_array()),
                    )]
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
            tag::ZONE_DEPOSIT => ZoneDepositIxData::deserialize(payload)
                .ok()
                .and_then(|data| {
                    decoded_instruction(
                        "zone_deposit",
                        zone_proofless_fields(data),
                        zone_proofless_accounts(payload, accounts.len()),
                    )
                }),
            tag::BATCH_UPDATE_NULLIFIER_TREE => decode(
                "batch_update_nullifier_tree",
                payload,
                |data: BatchUpdateNullifierTreeData| {
                    vec![
                        field("new_root", short_hex(&data.new_root)),
                        field("old_root", short_hex(&data.old_root)),
                        field("zkp_batch_index", data.zkp_batch_index.to_string()),
                    ]
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
    let Ok(data) = DepositIxData::deserialize(payload) else {
        return &[];
    };
    let has_cpi_signer = data.program.is_some();
    // SPL settlement carries one account more than SOL; cpi_signer (known from
    // the data) shifts both by one. This mirrors the program's own inference.
    let is_spl = account_count == 7 + usize::from(has_cpi_signer);
    if is_spl {
        &[
            "tree",
            "depositor",
            "user_token",
            "vault",
            "asset_registry",
            "token_program",
            "self_program",
        ]
    } else if has_cpi_signer || account_count == 7 {
        &[
            "tree",
            "depositor",
            "cpi_signer",
            "system_program",
            "sol_interface",
            "sol_source",
            "self_program",
        ]
    } else {
        &[
            "tree",
            "depositor",
            "system_program",
            "sol_interface",
            "sol_source",
            "self_program",
        ]
    }
}

fn zone_proofless_accounts(payload: &[u8], account_count: usize) -> &'static [&'static str] {
    let Ok(_data) = ZoneDepositIxData::deserialize(payload) else {
        return &[];
    };
    // Zone deposits always carry the zone_auth signer; SPL settlement adds one
    // account over SOL (8 vs 7), matching the program's own inference.
    if account_count == 8 {
        &[
            "tree",
            "depositor",
            "zone_auth",
            "user_token",
            "vault",
            "asset_registry",
            "token_program",
            "self_program",
        ]
    } else {
        &[
            "tree",
            "depositor",
            "zone_auth",
            "system_program",
            "sol_interface",
            "sol_source",
            "self_program",
        ]
    }
}

/// Names every account of a `transact` in builder order: `payer`, `tree`, the
/// optional `cpi_signer` (present iff the data carries one), the optional
/// public-amount accounts (SOL or SPL, present iff the data carries that public
/// amount), and the program account last for the `emit_event` self-CPI. Mirrors
/// the `Transact` builder layout. A pure shielded transfer carries no public
/// amount, so it names just `payer`, `tree`, `self_program`.
fn transact_accounts(data: &TransactIxData, account_count: usize) -> Vec<String> {
    let mut names: Vec<&str> = vec!["payer", "tree"];
    if data.cpi_signer.is_some() {
        names.push("cpi_signer");
    }
    // The public-amount accounts sit between cpi_signer and the trailing program
    // account; their count distinguishes an SPL withdrawal (carries cpi_authority)
    // from an SPL shield.
    let public_account_count = account_count.saturating_sub(names.len() + 1);
    if data.public_sol_amount.is_some() {
        names.extend(["sol_interface", "recipient", "system_program"]);
    } else if data.public_spl_amount.is_some() {
        if public_account_count == 5 {
            names.push("cpi_authority");
        }
        names.extend(["vault", "recipient", "user_token", "token_program"]);
    }
    names.push("self_program");
    names.into_iter().map(String::from).collect()
}

fn transact_fields(data: TransactIxData) -> Vec<DecodedField> {
    vec![
        field("expiry_unix_ts", data.expiry_unix_ts),
        field("relayer_fee", data.relayer_fee),
        field("inputs", data.inputs.len()),
        field("public_sol_amount", option_i64(data.public_sol_amount)),
        field("public_spl_amount", option_i64(data.public_spl_amount)),
        field("output_utxo_hashes", data.output_utxo_hashes.len()),
        field("output_ciphertexts", data.output_ciphertexts.len()),
        field("cpi_signer", data.cpi_signer.is_some()),
    ]
}

fn proofless_fields(data: DepositIxData) -> Vec<DecodedField> {
    vec![
        field("view_tag", short_hex(&data.view_tag)),
        field("owner", short_hex(&data.owner)),
        field("blinding", short_hex(&data.blinding)),
        field("public_amount", option_u64(data.public_amount)),
        field(
            "program_data_hash",
            option_hash(data.program.as_ref().map(|p| p.data_hash)),
        ),
        field(
            "program_data_len",
            data.program.as_ref().map_or(0, |p| p.data.len()),
        ),
        field(
            "cpi_signer",
            cpi_signer(data.program.as_ref().map(|p| p.cpi_signer)),
        ),
    ]
}

fn zone_proofless_fields(data: ZoneDepositIxData) -> Vec<DecodedField> {
    vec![
        field("view_tag", short_hex(&data.view_tag)),
        field("owner", short_hex(&data.owner)),
        field("blinding", short_hex(&data.blinding)),
        field("public_amount", option_u64(data.public_amount)),
        // The zone program id is no longer in instruction data; it lives in the
        // signing `ZoneConfig` account.
        field("zone_data_hash", option_hash(Some(data.zone_data_hash))),
        field("zone_data_len", data.zone_data.len()),
        field(
            "program_data_hash",
            option_hash(data.program.as_ref().map(|p| p.data_hash)),
        ),
        field(
            "program_data_len",
            data.program.as_ref().map_or(0, |p| p.data.len()),
        ),
    ]
}

fn proofless_view_fields(event: &GeneralEvent, data: &ProoflessOutput) -> Vec<DecodedField> {
    let slot = event.outputs.first();
    vec![
        field(
            "view_tag",
            slot.map_or_else(|| "?".to_string(), |s| short_hex(&s.view_tag)),
        ),
        field(
            "utxo_hash",
            slot.map_or_else(|| "?".to_string(), |s| short_hex(&s.utxo_hash)),
        ),
        field("leaf_index", event.first_output_leaf_index),
        field("owner", short_hex(&data.owner)),
        field("blinding", short_hex(&data.blinding)),
        field("zone_program_id", option_pubkey(data.zone_program_id)),
        field("zone_data_hash", option_hash(data.zone_data_hash)),
        field("program_data_hash", option_hash(data.program_data_hash)),
        field(
            "program_data_len",
            data.program_data.as_ref().map_or(0, Vec::len),
        ),
        field("zone_data_len", data.zone_data.as_ref().map_or(0, Vec::len)),
    ]
}

fn event_fields(event: GeneralEvent) -> Vec<DecodedField> {
    let mut fields = vec![
        field("event_kind", "general"),
        field("inputs", event.inputs.len()),
        field("outputs", event.outputs.len()),
        field("first_output_leaf_index", event.first_output_leaf_index),
        field("output_tree", pubkey(&event.output_tree)),
        field("relay_fee", option_u64(event.relay_fee)),
    ];
    if let Some(deposit_withdraw) = &event.deposit_withdraw {
        fields.extend([
            field("is_deposit", deposit_withdraw.is_deposit),
            field("amount", deposit_withdraw.amount),
            field("asset", option_pubkey(deposit_withdraw.asset)),
        ]);
    }
    if let Ok(proofless) = proofless_output(&event) {
        fields.push(field("output_data", "proofless"));
        fields.extend(proofless_view_fields(&event, &proofless));
    }
    fields
}

fn create_protocol_config_fields(data: CreateProtocolConfigData) -> Vec<DecodedField> {
    protocol_config_fields(
        data.protocol_authority.to_bytes(),
        data.tree_creation_authority.to_bytes(),
        data.tree_creation_is_permissionless != 0,
        data.forester_authority.to_bytes(),
        data.zone_creation_authority.to_bytes(),
        data.zone_creation_is_permissionless != 0,
        data.merge_authority.to_bytes(),
    )
}

fn update_protocol_config_fields(data: UpdateProtocolConfigData) -> Vec<DecodedField> {
    let decoded = match data {
        UpdateProtocolConfigData::ProtocolAuthority(a) => {
            field("protocol_authority", pubkey(&a.to_bytes()))
        }
        UpdateProtocolConfigData::TreeCreationAuthority(a) => {
            field("tree_creation_authority", pubkey(&a.to_bytes()))
        }
        UpdateProtocolConfigData::ForesterAuthority(a) => {
            field("forester_authority", pubkey(&a.to_bytes()))
        }
        UpdateProtocolConfigData::ZoneCreationAuthority(a) => {
            field("zone_creation_authority", pubkey(&a.to_bytes()))
        }
        UpdateProtocolConfigData::MergeAuthority(a) => {
            field("merge_authority", pubkey(&a.to_bytes()))
        }
        UpdateProtocolConfigData::TreeCreationPermissionless(b) => {
            field("tree_creation_is_permissionless", b)
        }
        UpdateProtocolConfigData::ZoneCreationPermissionless(b) => {
            field("zone_creation_is_permissionless", b)
        }
    };
    vec![decoded]
}

#[allow(clippy::too_many_arguments)]
fn protocol_config_fields(
    protocol_authority: [u8; 32],
    tree_creation_authority: [u8; 32],
    tree_creation_is_permissionless: bool,
    forester_authority: [u8; 32],
    zone_creation_authority: [u8; 32],
    zone_creation_is_permissionless: bool,
    merge_authority: [u8; 32],
) -> Vec<DecodedField> {
    vec![
        field("protocol_authority", pubkey(&protocol_authority)),
        field("tree_creation_authority", pubkey(&tree_creation_authority)),
        field(
            "tree_creation_is_permissionless",
            tree_creation_is_permissionless,
        ),
        field("forester_authority", pubkey(&forester_authority)),
        field("zone_creation_authority", pubkey(&zone_creation_authority)),
        field(
            "zone_creation_is_permissionless",
            zone_creation_is_permissionless,
        ),
        field("merge_authority", pubkey(&merge_authority)),
    ]
}

fn create_zone_config_fields(data: CreateZoneConfigData) -> Vec<DecodedField> {
    vec![
        field("program_id", pubkey(data.program_id.as_array())),
        field("authority", pubkey(data.authority.as_array())),
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
        instruction::{CpiData, CpiSignerData},
        SHIELDED_POOL_PROGRAM_ID,
    };

    use super::*;

    #[test]
    fn decodes_deposit() {
        let decoder = ZolanaInstructionDecoder {
            program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        };
        let mut data = vec![tag::DEPOSIT];
        data.extend_from_slice(
            &DepositIxData {
                view_tag: [1; 32],
                owner: [2; 32],
                blinding: [3; 31],
                public_amount: Some(42),
                program: Some(CpiData {
                    cpi_signer: CpiSignerData {
                        program_id: [4; 32],
                        bump: 255,
                    },
                    data_hash: [0u8; 32],
                    data: Vec::new(),
                }),
            }
            .serialize()
            .expect("serialize"),
        );

        let decoded = decoder.decode(&data, &[]).expect("decode");

        assert_eq!(decoded.name, "deposit");
        assert_eq!(decoded.account_names[2], "cpi_signer");
        assert!(decoded
            .fields
            .iter()
            .any(|field| field.name == "public_amount" && field.value == "42"));
    }
}
