use serde::{Deserialize, Serialize};
use solana_clock::{Slot, UnixTimestamp};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
    EncodedTransactionWithStatusMeta, UiConfirmedBlock, UiInstruction, UiTransactionStatusMeta,
};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use zolana_indexer_api::Hash;

use super::super::error::IngesterError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub data: Vec<u8>,
    pub accounts: Vec<Pubkey>,
    #[serde(default)]
    pub stack_height: Option<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionGroup {
    pub outer_instruction: Instruction,
    pub inner_instructions: Vec<Instruction>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub instruction_groups: Vec<InstructionGroup>,
    pub signature: Signature,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BlockInfo {
    pub metadata: BlockMetadata,
    pub transactions: Vec<TransactionInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BlockMetadata {
    pub slot: Slot,
    // In Solana, slots can be skipped. So there are not necessarily sequential.
    pub parent_slot: Slot,
    pub block_time: UnixTimestamp,
    pub blockhash: Hash,
    pub parent_blockhash: Hash,
    pub block_height: u64,
}

impl BlockMetadata {
    pub fn is_parent_of(&self, child: &Self) -> bool {
        child.parent_slot == self.slot && child.parent_blockhash == self.blockhash
    }
}

pub fn parse_ui_confirmed_blocked(
    block: UiConfirmedBlock,
    slot: Slot,
) -> Result<BlockInfo, IngesterError> {
    let UiConfirmedBlock {
        parent_slot,
        block_time,
        transactions,
        blockhash,
        previous_blockhash,
        block_height,
        ..
    } = block;

    let transactions: Result<Vec<_>, _> = transactions
        .unwrap_or_default()
        .into_iter()
        .map(parse_transaction_info)
        .collect();

    Ok(BlockInfo {
        transactions: transactions?,
        metadata: BlockMetadata {
            parent_slot,
            block_time: block_time
                .ok_or(IngesterError::ParserError("Missing block_time".to_string()))?,
            slot,
            blockhash: Hash::try_from(blockhash.as_str()).map_err(|e| {
                IngesterError::ParserError(format!("Failed to parse blockhash: {}", e))
            })?,
            parent_blockhash: Hash::try_from(previous_blockhash.as_str()).map_err(|e| {
                IngesterError::ParserError(format!("Failed to parse previous_blockhash: {}", e))
            })?,
            block_height: block_height.ok_or(IngesterError::ParserError(
                "Missing block_height".to_string(),
            ))?,
        },
    })
}

pub fn parse_transaction_info(
    transaction: EncodedTransactionWithStatusMeta,
) -> Result<TransactionInfo, IngesterError> {
    let EncodedTransactionWithStatusMeta {
        transaction, meta, ..
    } = transaction;

    let versioned_transaction: VersionedTransaction = transaction.decode().ok_or(
        IngesterError::ParserError("Transaction cannot be decoded".to_string()),
    )?;
    let meta = meta.ok_or(IngesterError::ParserError("Missing metadata".to_string()))?;

    let signature = *versioned_transaction.signatures.first().ok_or_else(|| {
        IngesterError::ParserError("Transaction is missing a signature".to_string())
    })?;
    let error = meta.clone().err.map(|e| e.to_string());
    let instruction_groups = parse_instruction_groups(versioned_transaction, meta)?;
    Ok(TransactionInfo {
        instruction_groups,
        signature,
        error,
    })
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Instruction {{ program_id: {}}}", self.program_id,)
    }
}

impl fmt::Display for InstructionGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InstructionGroup {{ outer_instruction: {}, inner_instructions: [{}] }}",
            self.outer_instruction,
            self.inner_instructions
                .iter()
                .map(Instruction::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

impl fmt::Display for TransactionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransactionInfo {{ instruction_groups: [{}] }}",
            self.instruction_groups
                .iter()
                .map(InstructionGroup::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl TryFrom<EncodedConfirmedTransactionWithStatusMeta> for TransactionInfo {
    type Error = IngesterError;

    fn try_from(tx: EncodedConfirmedTransactionWithStatusMeta) -> Result<Self, Self::Error> {
        let EncodedConfirmedTransactionWithStatusMeta { transaction, .. } = tx;

        let EncodedTransactionWithStatusMeta {
            transaction, meta, ..
        } = transaction;

        let versioned_transaction: VersionedTransaction = transaction.decode().ok_or(
            IngesterError::ParserError("Transaction cannot be decoded".to_string()),
        )?;
        let signature = *versioned_transaction.signatures.first().ok_or_else(|| {
            IngesterError::ParserError("Transaction is missing a signature".to_string())
        })?;
        let meta = meta.ok_or(IngesterError::ParserError("Missing metadata".to_string()))?;
        let error = meta.clone().err.map(|e| e.to_string());
        Ok(TransactionInfo {
            instruction_groups: parse_instruction_groups(versioned_transaction, meta.clone())?,
            signature,
            error,
        })
    }
}

pub fn parse_instruction_groups(
    versioned_transaction: VersionedTransaction,
    meta: UiTransactionStatusMeta,
) -> Result<Vec<InstructionGroup>, IngesterError> {
    let sdk_accounts = account_keys(&versioned_transaction, &meta)?;

    // Parse outer instructions and bucket them into groups
    let mut instruction_groups: Vec<InstructionGroup> = versioned_transaction
        .message
        .instructions()
        .iter()
        .map(|ix| {
            let program_id = sdk_account(
                &sdk_accounts,
                usize::from(ix.program_id_index),
                "outer instruction program id",
            )?;
            let data = ix.data.clone();
            let instruction_accounts: Result<Vec<Pubkey>, IngesterError> = ix
                .accounts
                .iter()
                .map(|account_index| {
                    sdk_account(
                        &sdk_accounts,
                        usize::from(*account_index),
                        "outer instruction account",
                    )
                })
                .collect();

            Ok(InstructionGroup {
                outer_instruction: Instruction {
                    program_id,
                    data,
                    accounts: instruction_accounts?,
                    stack_height: Some(1),
                },
                inner_instructions: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, IngesterError>>()?;

    // Parse inner instructions and place them into the correct instruction group
    if let OptionSerializer::Some(inner_instructions_vec) = meta.inner_instructions.as_ref() {
        for inner_instructions in inner_instructions_vec.iter() {
            let index = inner_instructions.index;
            for ui_instruction in inner_instructions.instructions.iter() {
                match ui_instruction {
                    UiInstruction::Compiled(ui_compiled_instruction) => {
                        let program_id = sdk_account(
                            &sdk_accounts,
                            usize::from(ui_compiled_instruction.program_id_index),
                            "inner instruction program id",
                        )?;
                        let data = bs58::decode(&ui_compiled_instruction.data)
                            .into_vec()
                            .map_err(|e| IngesterError::ParserError(e.to_string()))?;
                        let instruction_accounts: Result<Vec<Pubkey>, IngesterError> =
                            ui_compiled_instruction
                                .accounts
                                .iter()
                                .map(|account_index| {
                                    sdk_account(
                                        &sdk_accounts,
                                        usize::from(*account_index),
                                        "inner instruction account",
                                    )
                                })
                                .collect();
                        let instruction_group = instruction_groups
                            .get_mut(usize::from(index))
                            .ok_or_else(|| {
                                IngesterError::ParserError(format!(
                                    "Inner instruction group index {} is out of bounds",
                                    index
                                ))
                            })?;
                        instruction_group.inner_instructions.push(Instruction {
                            program_id,
                            data,
                            accounts: instruction_accounts?,
                            stack_height: ui_compiled_instruction.stack_height,
                        });
                    }
                    UiInstruction::Parsed(_) => {
                        return Err(IngesterError::ParserError(
                            "Parsed instructions are not implemented yet".to_string(),
                        ));
                    }
                }
            }
        }
    };

    Ok(instruction_groups)
}

/// The account list instruction indices address: the message's static keys,
/// then the addresses the runtime loaded from lookup tables, writable before
/// readonly.
fn account_keys(
    versioned_transaction: &VersionedTransaction,
    meta: &UiTransactionStatusMeta,
) -> Result<Vec<Pubkey>, IngesterError> {
    let message = &versioned_transaction.message;
    let mut accounts = Vec::from(message.static_account_keys());
    let uses_lookup_tables = message
        .address_table_lookups()
        .is_some_and(|lookups| !lookups.is_empty());
    match &meta.loaded_addresses {
        OptionSerializer::Some(loaded) => {
            for address in loaded.writable.iter().chain(loaded.readonly.iter()) {
                accounts.push(Pubkey::from_str(address).map_err(|e| {
                    IngesterError::ParserError(format!("invalid loaded address {address}: {e}"))
                })?);
            }
        }
        OptionSerializer::None | OptionSerializer::Skip => {
            if uses_lookup_tables {
                return Err(IngesterError::ParserError(
                    "transaction loads accounts through lookup tables but its metadata carries no loaded addresses".to_string(),
                ));
            }
        }
    }
    Ok(accounts)
}

fn sdk_account(accounts: &[Pubkey], index: usize, context: &str) -> Result<Pubkey, IngesterError> {
    accounts.get(index).copied().ok_or_else(|| {
        IngesterError::ParserError(format!(
            "{} account index {} is out of bounds for {} accounts",
            context,
            index,
            accounts.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Devnet slot 492480571.
    const VERSION_1_TRANSACTION: &str = r#"{
        "meta": {
            "computeUnitsConsumed": 150,
            "costUnits": 1481,
            "err": null,
            "fee": 10000,
            "innerInstructions": [],
            "loadedAddresses": {"readonly": [], "writable": []},
            "logMessages": [
                "Program 11111111111111111111111111111111 invoke [1]",
                "Program 11111111111111111111111111111111 success"
            ],
            "postBalances": [186075591481, 1000000, 1],
            "postTokenBalances": [],
            "preBalances": [186076601481, 0, 1],
            "preTokenBalances": [],
            "rewards": null,
            "status": {"Ok": null}
        },
        "transaction": [
            "gQEAAQ8AAADy9w1C57Jkve55/n0evk8h1V29Nq+WNjW/apyV99YdCAEDPJBEOvrHznm+JIY1gvt1x6JkQoct90T995JbS/vOpH2QdlSnm2Um+5lt81NwkwX9AGps4zj4PfkCUwgZYyu/GQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiBMAAAAAAADQBwAAAAABAAICDAAAAQIAAABAQg8AAAAAAFFfm76ICVd7iVN/uBVLqSdY6ZrZH0apLSUPPd+v+d9AsaMhO7GBd3wzf8mDxqeAvlE/UCIGuihGS/8w40CSDAE=",
            "base64"
        ],
        "version": 1
    }"#;

    // Devnet slot 508799716: a version 0 shielded-pool deposit that loads no
    // lookup table.
    const VERSION_0_DEPOSIT: &str = r#"{"meta":{"err":null,"status":{"Ok":null},"fee":5000,"preBalances":[18676128,23930254400,1488440,1488440,1,0,1,1066800,833120,20369267856],"postBalances":[18671128,23930254400,1488440,1488440,1,0,1,1066800,833120,20369267856],"innerInstructions":[{"index":1,"instructions":[{"programIdIndex":9,"accounts":[2,7,3,0],"data":"gvPShZQhKrzGM","stackHeight":2},{"programIdIndex":8,"accounts":[],"data":"2DdzFKysLDBMuANPWmpuTgr2ryZH5x1FSSNwS4CEsHzfUUYutpUUePviBeUMPgHaak9C2bSszk1j7TupcjyEqL6Hfxg2iVRcA8Hu3Gj1JDSreoKxDuu3f2GqRh31fZkFjPC6epFhrXixiPbTgG2TNEEoJjCXNebDpDLJVu5jUgLbr4cP7VmJZkA1itFX2z2CSGS7gvYhZo4AJPAFVZnk7k9NNVox1MMzN1FDwxgrLdEXCMs5pFk4WT97B2yZu2vWYu4HK3X1vz4N5PbFMogKLTB3JW2Rb1vJjFbFoHh9wvMPP5jBRMYg77xvPz6GNv5CuFG7LUkseVLdBmQ7J9DaQVxYTfDbuHH4yEwbXq6bMuCbbkkiC52nxmouhdtAfewMN54uE4y1M3tqRBnqzUV8mQKMX3dKDfiGStZo1AdNzoyL19ehtQxLqzitYBvmhdFBMVpkoTo","stackHeight":2}]}],"logMessages":[],"preTokenBalances":[],"postTokenBalances":[],"rewards":null,"loadedAddresses":{"writable":[],"readonly":[]},"computeUnitsConsumed":40087},"transaction":["AZSgsUs1lwKuk4kV/H6lcBS5a56e8FQWjHKWRlumu0vlil0i9LgZCp+W2nkiVc9Zb0edmu3BVDS6Lew0HeBOTgeAAQAGCsfSAbFW5dtTfOyGP+aa31AAhlraMvr01WNI+HwfXnj4Hk9ymFddIGHbkm/tzOnMxAgnPI/mt9TyQf4neFNRTB3UtGd2T2ab3zqow7rwofyuLXareWMn9SQjQx3JlCGS4/YkxUKmeq/Dvvlm8ae/swUv/lHq63pMEfKVq/jXlR5IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACRAl70pEGVI/o1tvhbQHyNPcTif6PFmbxDicN9JkzvNgMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAA92q1xD/zyzGxEJO9jRGadeyivT3bWdb+3JLuYwBm9rINBRvfUS7uJgsVS3WBKq3rgM+6NmTWOTdYplwz8jXvPQbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpk3pKuioAJsyweIxrRiy3XifM4ZgELKGS1NLLkjOQgeADBgAFAtDdBgAIBwEACAkHAgNPDwEB/QEAbZ4EBn45csw2BgpGLXxaFYU26Iqa6lt7eNWhoK9/8Qkk8H1n/eQvbYjL1wzVNw1EHdRgxIjipVhTzDNeW10pEkBCDwAAAAAAAAQDAAAFDAIAAAAAAAAAAAAAAAA=","base64"],"version":0}"#;

    // Devnet slot 508799716: a version 0 transaction whose instructions address
    // four writable and one readonly lookup-table accounts.
    const VERSION_0_WITH_LOOKUPS: &str = r#"{"meta":{"err":null,"status":{"Ok":null},"fee":5000,"preBalances":[49170000,1,833120,6329680,6329680,6329680,6329680,1188720],"postBalances":[49165000,1,833120,6329680,6329680,6329680,6329680,1188720],"innerInstructions":[],"logMessages":[],"preTokenBalances":[],"postTokenBalances":[],"rewards":null,"loadedAddresses":{"writable":["26bQ1aba173cQPgxFZFx4Es8dgXCLryzXmgLpezkxpY9","DuokWvuVUdQqtkCqzxVi9FMEG53S1RgkraSjC2y8tKbc","zsePY4VdVs1LxzziGXUnMjqNJrxqEgLUyzCWUt2uo7D","CMzRZeb4PpDVQVLvvEPcHEtfUEqV8BamPtn2unjkJ589"],"readonly":["EXjycYGbH88NdpgfcEkJqXp33T91NCcSFKiii9SazqAo"]},"computeUnitsConsumed":52124},"transaction":["AeQpRAf0XZzfGoWoD2sf1m7p3P5tjJgE99mMmhC+ll2h34wgXu+a6MkTwsdYQY8BMBFlBHDGeBI5+a9SRyHEaQSAAQACA5lN7tia5v412jQkNc+3acF3EgNzbNNPaZK9mqHQWbKkAwZGb+UhFzL/7K26csOb57yM5bvF9xJrLEObOkAAAACEi6WIL1dWYkvfRO/X7x1ySTrsxLqbiMKiaqVizLDcFJx7XF4pe3jPHCWGNhw1hD1sd7sVaJpHqoimEIM8kH2fBgEABQEAAAIAAQAFAgA1DAACAwAHA0eBsbaguODbBQCR+o3GpCQBjHzHagAAAAAM6BgsI9+xmgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQAAAAAAAAIDAAcER4GxtqC44NsFECoE+YhKBACMfMdqAAAAAAToGCwj37GaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAAAAAAgMABwVHgbG2oLjg2wVgPYoHHmcAAIx8x2oAAAAADOgYLCPfsZoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAAAAAAACAwAHBkeBsbaguODbBQDKDgu0/wgAjHzHagAAAAAM6BgsI9+xmgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQAAAAAAAAGgsNHgDHZdpgBijSJJ3/eInwm2+5qV9SCpeBaAZBeeLAQuMDI0AQE=","base64"],"version":0}"#;

    fn pubkey(key: &str) -> Pubkey {
        Pubkey::from_str(key).unwrap()
    }

    #[test]
    fn parses_version_0_transaction_without_lookups() {
        let transaction: EncodedTransactionWithStatusMeta =
            serde_json::from_str(VERSION_0_DEPOSIT).unwrap();
        let shielded_pool = pubkey("sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6");
        let tree = pubkey("33KVhbT4QtdQDrrrGwwThqD47Dh4Q6tA443t9jMNcWFN");

        let info = parse_transaction_info(transaction).unwrap();

        assert_eq!(
            info.signature,
            Signature::from_str(
                "3yMGsQ275aG65YsDoWEbNPNnGw7MuCq5MH2ne2PueBvcNGQ7ccKSkwhZgv2GmqXQYfBQpEF8eSvYTXdBKEA1Hn6r",
            )
            .unwrap()
        );
        assert_eq!(info.instruction_groups.len(), 3);
        let deposit = &info.instruction_groups[1];
        assert_eq!(deposit.outer_instruction.program_id, shielded_pool);
        assert_eq!(deposit.outer_instruction.data[0], 15);
        assert_eq!(deposit.outer_instruction.accounts[0], tree);
        let emitted_event = &deposit.inner_instructions[1];
        assert_eq!(emitted_event.program_id, shielded_pool);
        assert_eq!(emitted_event.data[0], 14);
        assert_eq!(emitted_event.stack_height, Some(2));
    }

    #[test]
    fn resolves_lookup_table_accounts_from_loaded_addresses() {
        let transaction: EncodedTransactionWithStatusMeta =
            serde_json::from_str(VERSION_0_WITH_LOOKUPS).unwrap();

        let info = parse_transaction_info(transaction).unwrap();

        let accounts: Vec<Vec<Pubkey>> = info
            .instruction_groups
            .iter()
            .skip(2)
            .map(|group| group.outer_instruction.accounts.clone())
            .collect();
        let payer = pubkey("BKSJXEd9nmKPHK6UPVWF2CySZpfK1RoYExBzpiMSuGaX");
        let readonly = pubkey("EXjycYGbH88NdpgfcEkJqXp33T91NCcSFKiii9SazqAo");
        assert_eq!(
            accounts,
            [
                "26bQ1aba173cQPgxFZFx4Es8dgXCLryzXmgLpezkxpY9",
                "DuokWvuVUdQqtkCqzxVi9FMEG53S1RgkraSjC2y8tKbc",
                "zsePY4VdVs1LxzziGXUnMjqNJrxqEgLUyzCWUt2uo7D",
                "CMzRZeb4PpDVQVLvvEPcHEtfUEqV8BamPtn2unjkJ589",
            ]
            .map(|writable| vec![payer, readonly, pubkey(writable)])
        );
    }

    #[test]
    fn rejects_lookup_table_transaction_without_loaded_addresses() {
        let mut transaction: EncodedTransactionWithStatusMeta =
            serde_json::from_str(VERSION_0_WITH_LOOKUPS).unwrap();
        transaction.meta.as_mut().unwrap().loaded_addresses = OptionSerializer::None;

        let error = parse_transaction_info(transaction).unwrap_err();

        assert!(error.to_string().contains("no loaded addresses"), "{error}");
    }

    #[test]
    fn parses_version_1_transaction() {
        let transaction: EncodedTransactionWithStatusMeta =
            serde_json::from_str(VERSION_1_TRANSACTION).unwrap();
        let payer = Pubkey::from_str("55R41dbRU13QhLpAgha1841wR5M6sAcZhXd4S1LGupBn").unwrap();
        let recipient = Pubkey::from_str("AivMvWMKoiXbqxok1xvW7ES5CWr3DG3TYR94iy1SBdBe").unwrap();
        let system_program = Pubkey::from_str("11111111111111111111111111111111").unwrap();

        assert_eq!(
            parse_transaction_info(transaction).unwrap(),
            TransactionInfo {
                instruction_groups: vec![InstructionGroup {
                    outer_instruction: Instruction {
                        program_id: system_program,
                        data: vec![2, 0, 0, 0, 64, 66, 15, 0, 0, 0, 0, 0],
                        accounts: vec![payer, recipient],
                        stack_height: Some(1),
                    },
                    inner_instructions: Vec::new(),
                }],
                signature: Signature::from_str(
                    "2dMwts34QC98z5E9dt16RcSr793Qe94DSFbgYyZwoT9TEmgNUuYBSNoKdtsV86o5yrR24P143y5o4qoeAyWzZ1Sg",
                )
                .unwrap(),
                error: None,
            }
        );
    }
}
