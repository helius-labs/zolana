use std::{
    cell::RefCell,
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use borsh::to_vec;
use p256::SecretKey;
use serde_json::{json, Map, Value};
use solana_account::Account;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction as SolanaTransaction;
use zolana_client::{
    assemble,
    error::ClientError,
    prover::{
        merge::{MergeProver, MergeProofInputs},
        MergeInputs, ProofCompressed, ProverClient,
    },
    retry::IndexerPollConfig,
    rpc::{Context, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse, Rpc},
    MerkleContext, MerkleProof, NonInclusionProof, ProverInputs, SpendProof,
};
use zolana_interface::{
    instruction::{CreateAssociatedTokenAccount, DepositIxData, MergeTransact, Transact},
    pda,
};
use zolana_keypair::{NullifierKey, PublicKey, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        merge::{PreparedMerge, MERGE_INPUTS},
        transact::{
            encode_confidential_slots, ConfidentialSplit, SppProofOutputUtxo, SPP_SUPPORTED_SHAPES,
        },
        types::SppProofInputUtxo,
    },
    serialization::split::{Split, SplitBundlePlaintext, SplitEncode},
    ApprovalRequest, AssetRegistry, Data, EncryptedSplit, EncryptedTransfer, LocalWalletAuthority,
    OutputContext, SyncWalletAuthority, TransactionError, Utxo, UtxoSerialization, Wallet,
    WalletUtxo, SOL_MINT,
};
use zolana_user_registry_interface::{
    instruction::discriminator, user_record_pda, user_registry_program_id, UserRecord,
};
use zolana_wallet::{
    build_deposit_transaction_sync, build_registration_transaction_sync,
    create_associated_token_account, create_merge, create_split, create_transfer_sync,
    create_withdrawal, get_private_token_balances, get_private_transactions,
    recipient_confidential_view_tag_sync, resolved_address_from_record,
    sign_shielded_transaction_sync, sync_wallet_with_config, Deposit, MergeParams, SplitParams,
    SyncWalletConfig, TransferParams, TransferRecipient, WithdrawalParams,
};

const SIGNING_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21,
];
const VIEWING_SEED: [u8; 32] = [22; 32];
const RECIPIENT_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23,
];
const BLINDING_SEED: [u8; 31] = [24; 31];

fn main() {
    match sections() {
        Ok(value) => println!(
            "{}",
            serde_json::to_string(&value).expect("serialize wallet fixtures")
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn sections() -> Result<Value, Box<dyn std::error::Error>> {
    let owner = fixed_keypair(SIGNING_SECRET, VIEWING_SEED)?;
    let recipient = fixed_keypair(RECIPIENT_SECRET, [25; 32])?;
    let mut sections = Map::new();
    sections.insert("create_associated_token_account".into(), ata_vectors()?);
    sections.insert("deposit".into(), deposit_vectors(&recipient)?);
    sections.insert("mod".into(), actions_mod_vectors());
    sections.insert("submit".into(), submit_vectors(&owner)?);
    sections.insert(
        "transaction".into(),
        transaction_vectors(&owner, &recipient)?,
    );
    sections.insert("lib".into(), lib_vectors());
    sections.insert(
        "user_registry".into(),
        user_registry_vectors(&owner, &recipient)?,
    );
    sections.insert("wallet_authority".into(), authority_vectors(&owner)?);
    sections.insert("wallet_sync".into(), wallet_sync_vectors(&owner)?);
    sections.insert("workflow_ata".into(), workflow_ata_vectors()?);
    sections.insert("workflow_merge".into(), workflow_merge_vectors(&owner)?);
    sections.insert("workflow_split".into(), workflow_split_vectors(&owner)?);
    Ok(Value::Object(sections))
}

fn fixed_keypair(
    signing_secret: [u8; 32],
    viewing_seed: [u8; 32],
) -> Result<ShieldedKeypair, Box<dyn std::error::Error>> {
    Ok(ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&signing_secret)?,
        ViewingKey::from_seed(&viewing_seed, 0)?,
    )?)
}

fn section(inputs: Value, expected: Value) -> Value {
    let mut inputs = inputs.as_object().cloned().unwrap_or_default();
    inputs.insert("testOnlySecret".into(), Value::Bool(true));
    json!({"inputs": inputs, "expected": expected})
}

fn error(error: &impl std::fmt::Debug) -> Value {
    let details = format!("{error:?}");
    let code = details.split(['(', ' ', '{']).next().unwrap_or("Unknown");
    json!({"code": code, "details": details})
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn instruction_json(instruction: &Instruction) -> Value {
    json!({
        "programId": instruction.program_id.to_string(),
        "accounts": instruction.accounts.iter().map(|account| json!({
            "address": account.pubkey.to_string(),
            "signer": account.is_signer,
            "writable": account.is_writable
        })).collect::<Vec<_>>(),
        "dataBytes": hex(&instruction.data)
    })
}

fn transaction_json(transaction: &SolanaTransaction) -> Value {
    json!({
        "messageBytes": hex(&bincode::serialize(&transaction.message).expect("serialize message")),
        "signatures": transaction.signatures.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "requiredSignatures": transaction.message.header.num_required_signatures.to_string()
    })
}

#[derive(Default)]
struct MockRpc {
    account: Option<(Address, Account)>,
    blockhash: Hash,
    send_error: Option<String>,
    sent: RefCell<Vec<SolanaTransaction>>,
}

impl Rpc for MockRpc {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Ok(self
            .account
            .as_ref()
            .and_then(|(expected, account)| (*expected == address).then(|| account.clone())))
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((self.blockhash, 1))
    }

    fn send_transaction(&self, transaction: &SolanaTransaction) -> Result<Signature, ClientError> {
        if let Some(message) = &self.send_error {
            return Err(ClientError::Rpc(message.clone()));
        }
        self.sent.borrow_mut().push(transaction.clone());
        Ok(Signature::default())
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<zolana_client::retry::IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Ok(GetEncryptedUtxosByTagsResponse {
            context: Context { block_time: 0 },
            matches: Vec::new(),
            next_cursor: None,
        })
    }

    fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<zolana_client::retry::IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context { block_time: 0 },
            transactions: Vec::new(),
            next_cursor: None,
        })
    }
}

fn ata_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let payer = Keypair::new_from_array([26; 32]);
    let owner = Pubkey::new_from_array([27; 32]);
    let mint = Pubkey::new_from_array([28; 32]);
    let rpc = MockRpc {
        blockhash: Hash::new_from_array([29; 32]),
        ..Default::default()
    };
    let (_, ata) = create_associated_token_account(&rpc, &payer, &owner, &mint)?;
    let sent = rpc.sent.borrow();
    let transaction = sent.first().expect("ATA transaction");
    let builder = CreateAssociatedTokenAccount {
        payer: payer.pubkey(),
        owner,
        mint,
    };
    Ok(section(
        json!({
            "payerSecretBytes": hex(&[26; 32]),
            "owner": owner.to_string(),
            "mint": mint.to_string()
        }),
        json!({
            "address": ata.to_string(),
            "canonicalAddress": pda::associated_token_address(&owner, &mint).to_string(),
            "instruction": instruction_json(&builder.instruction()),
            "transaction": transaction_json(transaction),
            "idempotentDiscriminator": builder.instruction().data[0].to_string()
        }),
    ))
}

fn workflow_ata_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let payer = Keypair::new_from_array([26; 32]);
    let owner = Pubkey::new_from_array([27; 32]);
    let mint = Pubkey::new_from_array([28; 32]);
    let blockhash = Hash::new_from_array([29; 32]);
    let rpc = MockRpc {
        blockhash,
        ..Default::default()
    };
    let first = create_associated_token_account(&rpc, &payer, &owner, &mint)?;
    let second = create_associated_token_account(&rpc, &payer, &owner, &mint)?;
    let sent = rpc.sent.borrow();
    let first_transaction = sent.first().expect("first ATA transaction");
    let second_transaction = sent.get(1).expect("second ATA transaction");
    let failure = create_associated_token_account(
        &MockRpc {
            blockhash,
            send_error: Some("fixture submission rejected".into()),
            ..Default::default()
        },
        &payer,
        &owner,
        &mint,
    )
    .expect_err("RPC failure must propagate");
    let builder = CreateAssociatedTokenAccount {
        payer: payer.pubkey(),
        owner,
        mint,
    };

    Ok(section(
        json!({
            "accountInitiallyExists": false,
            "blockhashBytes": hex(blockhash.as_ref()),
            "mint": mint.to_string(),
            "owner": owner.to_string(),
            "payerSecretBytes": hex(&[26; 32])
        }),
        json!({
            "address": first.1.to_string(),
            "firstCreate": {
                "accountExistsAfter": true,
                "createdAccountCount": "1",
                "instruction": instruction_json(&builder.instruction()),
                "signature": first.0.to_string(),
                "transaction": transaction_json(first_transaction)
            },
            "idempotentRepeat": {
                "accountExistsAfter": true,
                "balanceDelta": "0",
                "createdAccountCount": "1",
                "instructionMessageUnchanged": first_transaction.message == second_transaction.message,
                "signature": second.0.to_string(),
                "transaction": transaction_json(second_transaction)
            },
            "submissionCount": sent.len().to_string(),
            "typedError": error(&failure)
        }),
    ))
}

fn deposit_vectors(recipient: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let owner = recipient.owner_hash()?;
    let blinding = derive_blinding(&BLINDING_SEED, 0);
    let amount = 42u64;
    let data = DepositIxData {
        view_tag: recipient.shielded_address()?.confidential_view_tag()?,
        owner,
        blinding,
        amount,
        utxo_data: None,
        memo: Some(b"wallet fixture".to_vec()),
    };
    let deposit = Deposit {
        utxo_hash: zolana_transaction::ProofInputUtxo::new(owner, &SOL_MINT, amount, &blinding)?
            .hash()?,
        data,
        asset: SOL_MINT,
        spl: None,
    };
    let payer = Pubkey::new_from_array([30; 32]);
    let tree = Pubkey::new_from_array([31; 32]);
    let blockhash = Hash::new_from_array([32; 32]);
    let transaction = build_deposit_transaction_sync(
        &MockRpc {
            blockhash,
            ..Default::default()
        },
        payer,
        tree,
        payer,
        &deposit,
    )?;
    let mint = Pubkey::new_from_array([33; 32]);
    let missing_spl = zolana_wallet::create_deposit(zolana_wallet::DepositParams {
        recipient: &recipient.shielded_address()?,
        asset: Address::new_from_array(mint.to_bytes()),
        amount,
        spl_token_account: None,
        memo: None,
    })
    .expect_err("SPL token account required");
    Ok(section(
        json!({
            "recipientSigningSecretBytes": hex(&RECIPIENT_SECRET),
            "recipientViewingSeedBytes": hex(&[25; 32]),
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "amount": amount.to_string(),
            "payer": payer.to_string(),
            "tree": tree.to_string(),
            "blockhashBytes": hex(blockhash.as_ref())
        }),
        json!({
            "sol": {
                "assetBytes": hex(deposit.asset.as_array()),
                "ownerBytes": hex(&deposit.data.owner),
                "viewTagBytes": hex(&deposit.data.view_tag),
                "blindingBytes": hex(&deposit.data.blinding),
                "utxoHashBytes": hex(&deposit.utxo_hash),
                "instruction": instruction_json(&deposit.instruction(tree, payer)),
                "unsignedTransaction": transaction_json(&transaction)
            },
            "spl": {
                "missingTokenAccountError": error(&missing_spl),
                "vault": pda::spl_asset_vault(&mint).to_string(),
                "registry": pda::spl_asset_registry(&mint).to_string()
            }
        }),
    ))
}

fn actions_mod_vectors() -> Value {
    section(
        json!({}),
        json!({
            "exports": [
                "create_associated_token_account", "create_deposit", "create_merge",
                "create_split", "create_transfer", "create_withdrawal",
                "build_private_transaction", "sign_private_transaction",
                "submit_merge_transaction"
            ],
            "routing": {"solAssetBytes": hex(SOL_MINT.as_array()), "splRequiresSettlementAccounts": true}
        }),
    )
}

fn wallet_with_amounts(
    keypair: &ShieldedKeypair,
    amounts: &[u64],
) -> Result<Wallet, Box<dyn std::error::Error>> {
    let mut wallet = Wallet::new(keypair.shielded_address()?, AssetRegistry::default())?;
    for (position, amount) in amounts.iter().copied().enumerate() {
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding: derive_blinding(&BLINDING_SEED, position as u8),
            zone_program_id: None,
            data: Data::default(),
        };
        let nullifier_key = keypair.nullifier_key.pubkey()?;
        let hash = utxo.hash(&nullifier_key, &[0; 32], &[0; 32])?;
        wallet.utxos.push(WalletUtxo {
            nullifier: utxo.nullifier(&hash, &keypair.nullifier_key)?,
            utxo,
            output_context: OutputContext {
                hash,
                tree: Address::new_from_array([34; 32]),
                leaf_index: position as u64,
            },
            data_hash: None,
            zone_data_hash: None,
            spent: false,
        });
    }
    Ok(wallet)
}

fn transaction_vectors(
    owner: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
) -> Result<Value, Box<dyn std::error::Error>> {
    let wallet = wallet_with_amounts(owner, &[20, 50, 10])?;
    let payer = Address::new_from_array([35; 32]);
    let recipient_owner = Pubkey::new_from_array([36; 32]);
    let (record_pda, bump) = user_record_pda(&recipient_owner);
    let record = record(recipient_owner, bump, recipient, false)?;
    let registered_rpc = MockRpc {
        account: Some((
            Address::new_from_array(record_pda.to_bytes()),
            account(&record),
        )),
        ..Default::default()
    };
    let registered = create_transfer_sync(TransferParams {
        rpc: &registered_rpc,
        wallet: &wallet,
        payer,
        recipient: recipient_owner,
        asset: SOL_MINT,
        amount: 60,
    })?;
    let fallback = create_transfer_sync(TransferParams {
        rpc: &MockRpc::default(),
        wallet: &wallet,
        payer,
        recipient: recipient_owner,
        asset: SOL_MINT,
        amount: 60,
    })?;
    let split = create_split(SplitParams {
        wallet: &wallet_with_amounts(owner, &[1001, 800])?,
        payer,
        asset: SOL_MINT,
        parts: 2,
        input: None,
    })?;
    let merge = create_merge(MergeParams {
        wallet: &wallet,
        keypair: owner,
        asset: SOL_MINT,
        inputs: None,
        tree: None,
    })?;
    let duplicate = match create_merge(MergeParams {
        wallet: &wallet,
        keypair: owner,
        asset: SOL_MINT,
        inputs: Some(vec![
            wallet.utxos[0].output_context.hash,
            wallet.utxos[0].output_context.hash,
        ]),
        tree: None,
    }) {
        Ok(_) => panic!("duplicate merge input accepted"),
        Err(error) => error,
    };
    let authority = DeterministicAuthority {
        local: LocalWalletAuthority::new(payer, owner),
    };
    let signed = sign_shielded_transaction_sync(
        create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer,
            recipient: recipient_owner,
            asset: SOL_MINT,
            amount: 60,
        })?
        .transaction,
        &wallet,
        &authority,
    )?;
    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "walletAmounts": ["20", "50", "10"],
            "requestedAmount": "60"
        }),
        json!({
            "registered": {
                "kind": match registered.recipient { TransferRecipient::Registered(_) => "private", _ => "unexpected" },
                "selectedInputCount": registered.transaction.input_count().to_string(),
                "treeBytes": hex(registered.transaction.tree().as_array())
            },
            "publicFallback": {
                "kind": if fallback.recipient.is_public_withdrawal() { "publicWithdrawal" } else { "unexpected" },
                "withdrawal": format!("{:?}", fallback.recipient.withdrawal())
            },
            "split": {
                "inputCount": split.transaction.input_count().to_string(),
                "outputs": split.num_outputs.to_string(),
                "perOutputAmount": split.per_output_amount.to_string()
            },
            "merge": {
                "selectedAmounts": merge.prepared.inputs.iter().filter(|input| !input.is_dummy()).map(|input| input.utxo.amount.to_string()).collect::<Vec<_>>(),
                "realInputCount": merge.num_inputs.to_string(),
                "paddedInputCount": merge.prepared.inputs.len().to_string(),
                "mergedAmount": merge.merged_amount.to_string(),
                "duplicateError": error(&duplicate)
            },
            "signed": {
                "p256SignaturePresent": signed.transaction.p256_signature.is_some(),
                "inputContexts": signed.transaction.input_utxo_hashes()?.iter().map(|input| json!({
                    "index": input.index.to_string(),
                    "utxoHashBytes": hex(&input.utxo_hash),
                    "nullifierBytes": hex(&input.nullifier)
                })).collect::<Vec<_>>()
            },
            "ordering": ["encrypt", "approve", "finalize", "p256Sign"],
            "custody": {
                "unsignedNativeMessageOracle": "client/rpc-indexer-v1.json expected.legacyMessages",
                "signerEquivalence": "same message bytes; only the fee-payer signature changes"
            }
        }),
    ))
}

struct DeterministicAuthority<'a> {
    local: LocalWalletAuthority<'a>,
}

impl SyncWalletAuthority for DeterministicAuthority<'_> {
    fn solana_pubkey(&self) -> Address {
        SyncWalletAuthority::solana_pubkey(&self.local)
    }

    fn shielded_address(&self) -> Result<zolana_keypair::ShieldedAddress, TransactionError> {
        SyncWalletAuthority::shielded_address(&self.local)
    }

    fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError> {
        SyncWalletAuthority::viewing_keys(&self.local)
    }

    fn encrypt_confidential_transfer(
        &self,
        _first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> Result<EncryptedTransfer, TransactionError> {
        let tx = ViewingKey::from_seed(&[46; 32], 0)?;
        let salt = [47; 16];
        Ok(EncryptedTransfer {
            tx_viewing_pk: tx.pubkey(),
            salt,
            payload: encode_confidential_slots(outputs, assets, &tx, salt)?,
        })
    }

    fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: [u8; 32],
        sender: &zolana_transaction::serialization::anonymous::AnonymousTransferSenderPlaintext,
        recipients: &[zolana_transaction::AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_anonymous_transfer(
            &self.local,
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    fn encrypt_split(
        &self,
        _first_nullifier: &[u8; 32],
        view_tag: [u8; 32],
        bundle: &SplitBundlePlaintext,
    ) -> Result<EncryptedSplit, TransactionError> {
        let tx = ViewingKey::from_seed(&[48; 32], 0)?;
        let salt = [49; 16];
        Ok(EncryptedSplit {
            tx_viewing_pk: tx.pubkey(),
            salt,
            payload: Split::encode_plaintext(
                bundle,
                view_tag,
                &SplitEncode {
                    tx,
                    recipient_pubkey: self.local.shielded_address()?.viewing_pubkey,
                    salt,
                    slot_index: 0,
                    blinding_seed: bundle.blinding_seed,
                },
            )?,
        })
    }

    fn sign_p256(
        &self,
        message_hash: &[u8; 32],
    ) -> Result<zolana_transaction::P256Signature, TransactionError> {
        SyncWalletAuthority::sign_p256(&self.local, message_hash)
    }

    fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError> {
        SyncWalletAuthority::spend_nullifier_key(&self.local)
    }
}

fn proof_output_json(output: &SppProofOutputUtxo) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "amount": output.amount.to_string(),
        "assetBytes": hex(output.asset.as_array()),
        "blindingBytes": hex(&output.blinding),
        "isDummy": output.is_dummy(),
        "ownerHashBytes": hex(&output.owner_hash()?),
        "utxoHashBytes": hex(&output.hash()?)
    }))
}

fn workflow_split_vectors(owner: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let payer = Address::new_from_array([35; 32]);
    let wallet = wallet_with_amounts(owner, &[1001, 800])?;
    let created = create_split(SplitParams {
        wallet: &wallet,
        payer,
        asset: SOL_MINT,
        parts: 2,
        input: None,
    })?;
    let selected_entry = wallet
        .utxos
        .iter()
        .find(|entry| entry.utxo.amount == 800)
        .expect("divisible split input");
    let selected_hash = selected_entry.output_context.hash;
    let input_count = created.transaction.input_count();
    let tree = created.transaction.tree();
    let unsigned = created.transaction.clone();
    let authority = DeterministicAuthority {
        local: LocalWalletAuthority::new(payer, owner),
    };
    let mut deterministic_split = ConfidentialSplit::new(
        owner.shielded_address()?,
        SppProofInputUtxo::new(selected_entry.utxo.clone(), owner),
        SOL_MINT,
        created.num_outputs,
        created.per_output_amount,
        payer,
    )?;
    deterministic_split.blinding_seed = BLINDING_SEED;
    let prepared = deterministic_split.prepare()?;
    let bundle = prepared.bundle_plaintext(&wallet.registry)?;
    let encrypted = authority.encrypt_split(
        &prepared.first_nullifier,
        prepared.owner_view_tag()?,
        &bundle,
    )?;
    let mut signed =
        prepared.finalize(encrypted.tx_viewing_pk, encrypted.salt, encrypted.payload)?;
    signed.sign_p256(owner)?;
    let input = SppProofInputUtxo::new(selected_entry.utxo.clone(), owner);
    let input_proof = spend_proof(&input, tree, 0)?;
    let assembled = assemble(signed.clone(), std::slice::from_ref(&input_proof))?;
    let (prover_request, compressed) = deterministic_transfer_proof(&assembled.prover_inputs)?;
    let transact_data = assembled.with_proof(compressed.to_transact_proof());
    let transact_instruction = Transact {
        payer: Pubkey::new_from_array(payer.to_bytes()),
        tree: Pubkey::new_from_array(tree.to_bytes()),
        withdrawal: None,
        data: transact_data,
    }
    .instruction();
    let submit_instructions = [
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        transact_instruction.clone(),
    ];
    let blockhash = Hash::new_from_array([54; 32]);
    let payer_pubkey = Pubkey::new_from_array(payer.to_bytes());
    let mut submitted =
        SolanaTransaction::new_with_payer(&submit_instructions, Some(&payer_pubkey));
    submitted.message.recent_blockhash = blockhash;
    let mut tampered_wallet = wallet_with_amounts(owner, &[1001, 800])?;
    tampered_wallet
        .utxos
        .iter_mut()
        .find(|entry| entry.output_context.hash == selected_hash)
        .expect("selected split input")
        .spent = true;
    let tamper_error = match sign_shielded_transaction_sync(unsigned, &tampered_wallet, &authority)
    {
        Ok(_) => panic!("spent split input accepted"),
        Err(error) => error,
    };
    let output_amounts = signed
        .output_utxos
        .iter()
        .map(|output| output.amount)
        .collect::<Vec<_>>();

    Ok(section(
        json!({
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "deterministicEncryptionSaltBytes": hex(&[49; 16]),
            "deterministicTxViewingSeedBytes": hex(&[48; 32]),
            "parts": "2",
            "payerBytes": hex(payer.as_array()),
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "walletAmounts": ["1001", "800"]
        }),
        json!({
            "creation": {
                "inputCount": input_count.to_string(),
                "outputCount": created.num_outputs.to_string(),
                "perOutputAmount": created.per_output_amount.to_string(),
                "selectedInputHashBytes": hex(&selected_hash),
                "treeBytes": hex(tree.as_array())
            },
            "signed": {
                "encryptedBundleBytes": signed.external_data.outputs.first().and_then(|output| output.data.as_ref()).map(|bytes| hex(bytes)),
                "externalDataHashBytes": hex(&signed.external_data.hash()?),
                "inputContexts": signed.input_utxo_hashes()?.iter().map(|input| json!({
                    "index": input.index.to_string(),
                    "nullifierBytes": hex(&input.nullifier),
                    "utxoHashBytes": hex(&input.utxo_hash)
                })).collect::<Vec<_>>(),
                "messageHashBytes": hex(&signed.message_hash()?),
                "outputs": signed.output_utxos.iter().map(proof_output_json).collect::<Result<Vec<_>, _>>()?,
                "p256SignatureBytes": signed.p256_signature.map(|signature| hex(&signature)),
                "wireOutputs": signed.external_data.outputs.iter().map(|output| json!({
                    "dataBytes": output.data.as_ref().map(|bytes| hex(bytes)),
                    "ownerTag": format!("{:?}", output.owner_tag),
                    "utxoHashBytes": hex(&output.utxo_hash)
                })).collect::<Vec<_>>()
            },
            "stateTransition": {
                "conservedAmount": output_amounts.iter().sum::<u64>().to_string(),
                "paddingOutputCount": output_amounts.iter().filter(|amount| **amount == 0).count().to_string(),
                "realOutputAmounts": output_amounts.iter().filter(|amount| **amount != 0).map(ToString::to_string).collect::<Vec<_>>(),
                "repeatedSyncAddsHistory": "0",
                "repeatedSyncAddsUtxos": "0",
                "spentInputHashBytes": hex(&selected_hash)
            },
            "submission": {
                "computeUnitLimit": "1400000",
                "instruction": instruction_json(&transact_instruction),
                "message": transaction_json(&submitted),
                "proverRequest": prover_request,
                "submittedSignature": Signature::default().to_string()
            },
            "tamperEvidence": error(&tamper_error)
        }),
    ))
}

fn deterministic_dummy(position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo {
        utxo: Utxo {
            owner: PublicKey::zeroed(),
            asset: SOL_MINT,
            amount: 0,
            blinding: derive_blinding(&BLINDING_SEED, position),
            zone_program_id: None,
            data: Data::default(),
        },
        nullifier_key: NullifierKey::from_secret([0; 31]),
        data_hash: None,
        zone_data_hash: None,
    }
}

fn field_byte(byte: u8) -> [u8; 32] {
    let mut value = [0; 32];
    value[31] = byte;
    value
}

fn spend_proof(
    input: &SppProofInputUtxo,
    tree: Address,
    index: usize,
) -> Result<SpendProof, TransactionError> {
    Ok(SpendProof {
        state: MerkleProof {
            leaf: input.hash()?,
            merkle_context: MerkleContext { tree_type: 1, tree },
            path: vec![field_byte(60 + index as u8); 32],
            leaf_index: index as u64,
            root: field_byte(70),
            root_seq: 71,
            root_index: 72 + index as u16,
        },
        nullifier: NonInclusionProof {
            leaf: input.nullifier()?,
            merkle_context: MerkleContext { tree_type: 2, tree },
            path: vec![field_byte(80 + index as u8); 40],
            low_element: field_byte(90),
            low_element_index: 0,
            high_element: field_byte(91),
            high_element_index: 1,
            root: field_byte(92),
            root_seq: 93,
            root_index: 94 + index as u16,
        },
    })
}

fn read_http_body(stream: &mut impl Read) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err("merge proof request ended before headers".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec())?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then_some(value)
        })
        .ok_or("merge proof request lacks content-length")?
        .trim()
        .parse::<usize>()?;
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err("merge proof request body was truncated".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes[header_end..header_end + content_length].to_vec())
}

fn field_hex(field: &ark_bn254::Fq) -> String {
    format!("0x{}", hex(&field.into_bigint().to_bytes_be()))
}

fn gnark_bsb22_proof() -> Value {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let pair = |x: &ark_bn254::Fq, y: &ark_bn254::Fq| vec![field_hex(x), field_hex(y)];
    // Prover WriteRawTo / EIP-197: each Fp2 is (A1, A0), not ark (c0, c1).
    json!({
        "proof": {
            "ar": pair(&g1.x, &g1.y),
            "bs": [
                pair(&g2.x.c1, &g2.x.c0),
                pair(&g2.y.c1, &g2.y.c0)
            ],
            "krs": pair(&g1.x, &g1.y),
            "proof_commitment": pair(&g1.x, &g1.y),
            "proof_commitment_pok": pair(&g1.x, &g1.y)
        }
    })
}

fn start_proof_server(
) -> Result<(String, thread::JoinHandle<Result<Vec<u8>, String>>), Box<dyn std::error::Error>> {
    let response = serde_json::to_vec(&gnark_bsb22_proof())?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || -> Result<Vec<u8>, String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let request = read_http_body(&mut stream).map_err(|error| error.to_string())?;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .map_err(|error| error.to_string())?;
        stream
            .write_all(&response)
            .map_err(|error| error.to_string())?;
        Ok(request)
    });
    Ok((format!("http://{address}"), server))
}

fn deterministic_merge_proof(
    inputs: &MergeInputs,
) -> Result<(Value, ProofCompressed), Box<dyn std::error::Error>> {
    let (url, server) = start_proof_server()?;
    let proof = ProverClient::new(url).prove_merge(inputs)?;
    let request = server
        .join()
        .map_err(|_| "merge proof fixture server panicked")??;
    Ok((
        serde_json::from_slice(&request)?,
        ProofCompressed::try_from(proof)?,
    ))
}

fn deterministic_transfer_proof(
    inputs: &ProverInputs,
) -> Result<(Value, ProofCompressed), Box<dyn std::error::Error>> {
    let (url, server) = start_proof_server()?;
    let client = ProverClient::new(url);
    let proof = match inputs {
        ProverInputs::Eddsa(inputs) => client.prove_transfer(inputs)?,
        ProverInputs::P256(inputs) => client.prove_transfer_p256(inputs)?,
    };
    let request = server
        .join()
        .map_err(|_| "transfer proof fixture server panicked")??;
    Ok((
        serde_json::from_slice(&request)?,
        ProofCompressed::try_from(proof)?,
    ))
}

fn workflow_merge_vectors(owner: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let wallet = wallet_with_amounts(owner, &[20, 50, 10])?;
    let created = create_merge(MergeParams {
        wallet: &wallet,
        keypair: owner,
        asset: SOL_MINT,
        inputs: None,
        tree: None,
    })?;
    let selected = wallet
        .utxos
        .iter()
        .filter(|entry| [10, 20, 50].contains(&entry.utxo.amount))
        .map(|entry| SppProofInputUtxo::new(entry.utxo.clone(), owner))
        .collect::<Vec<_>>();
    let mut selected = [10, 20, 50]
        .into_iter()
        .map(|amount| {
            selected
                .iter()
                .find(|input| input.utxo.amount == amount)
                .expect("selected merge input")
                .clone()
        })
        .collect::<Vec<_>>();
    let real_inputs = selected.clone();
    for position in selected.len()..MERGE_INPUTS {
        selected.push(deterministic_dummy(position as u8));
    }
    let output = SppProofOutputUtxo {
        owner_address: Some(owner.shielded_address()?),
        owner_tag: Some(owner.signing_pubkey().confidential_view_tag()?),
        asset: SOL_MINT,
        amount: 80,
        blinding: derive_blinding(&BLINDING_SEED, 20),
        ..Default::default()
    };
    let tx_viewing_sk = SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 15,
    ])?;
    let prepared = PreparedMerge {
        inputs: selected,
        output,
        expiry_unix_ts: u64::MAX,
        signing_pubkey: owner.signing_pubkey(),
        user_viewing_pk: owner.viewing_pubkey(),
        tx_viewing_sk,
    };
    let tree = Address::new_from_array([34; 32]);
    let proofs = real_inputs
        .iter()
        .enumerate()
        .map(|(index, input)| spend_proof(input, tree, index))
        .collect::<Result<Vec<_>, _>>()?;
    let material = zolana_wallet::actions::submit::MergeMaterial::from_keypair(owner);
    let result = MergeProver::try_from(MergeProofInputs {
        prepared,
        nullifier_key: material.nullifier_key.clone(),
        proofs: proofs.clone(),
    })?
    .build()?;
    let (prover_request, compressed) = deterministic_merge_proof(&result.inputs)?;
    let payer = Keypair::new_from_array([51; 32]);
    let owner_pubkey = Pubkey::new_from_array([50; 32]);
    let (record_pda, bump) = user_record_pda(&owner_pubkey);
    let enabled_record = record(owner_pubkey, bump, owner, true)?;
    let merge_instruction = MergeTransact {
        tree: Pubkey::new_from_array(tree.to_bytes()),
        payer: payer.pubkey(),
        user_record: record_pda,
        data: result.instruction_data(compressed.to_merge_proof()?),
    }
    .instruction();
    let instructions = [
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        merge_instruction.clone(),
    ];
    let blockhash = Hash::new_from_array([52; 32]);
    let mut transaction = SolanaTransaction::new_with_payer(&instructions, Some(&payer.pubkey()));
    transaction.message.recent_blockhash = blockhash;
    let disabled_error = ClientError::MergeDisabled {
        owner: owner_pubkey,
    };
    let tree_error = ClientError::MergeTreeMismatch {
        proof_tree: [53; 32],
        submit_tree: tree.to_bytes(),
    };
    let duplicate_error = match create_merge(MergeParams {
        wallet: &wallet,
        keypair: owner,
        asset: SOL_MINT,
        inputs: Some(vec![
            wallet.utxos[0].output_context.hash,
            wallet.utxos[0].output_context.hash,
        ]),
        tree: None,
    }) {
        Ok(_) => panic!("duplicate merge input accepted"),
        Err(error) => error,
    };

    Ok(section(
        json!({
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "blockhashBytes": hex(blockhash.as_ref()),
            "enabledRecord": {
                "accountDataBytes": hex(&account(&enabled_record).data),
                "bump": bump.to_string(),
                "mergingEnabled": enabled_record.merging_enabled,
                "owner": owner_pubkey.to_string(),
                "pda": record_pda.to_string()
            },
            "payerSecretBytes": hex(&[51; 32]),
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "tree": Pubkey::new_from_array(tree.to_bytes()).to_string(),
            "txViewingSecretBytes": format!("{:064x}", 15),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "walletAmounts": ["20", "50", "10"]
        }),
        json!({
            "creation": {
                "mergedAmount": created.merged_amount.to_string(),
                "realInputCount": created.num_inputs.to_string(),
                "selectedAmounts": ["10", "20", "50"],
                "treeBytes": hex(created.tree.as_array())
            },
            "material": {
                "nullifierPubkeyBytes": hex(&material.nullifier_key.pubkey()?),
                "signingPubkeyBytes": hex(material.signing_pubkey.as_bytes()),
                "viewingPubkeyBytes": hex(material.viewing_pubkey.as_bytes())
            },
            "proof": {
                "compressed": {
                    "aBytes": hex(&compressed.a),
                    "bBytes": hex(&compressed.b),
                    "cBytes": hex(&compressed.c),
                    "commitmentBytes": hex(&compressed.commitment.expect("commitment").commitment),
                    "commitmentPokBytes": hex(&compressed.commitment.expect("commitment").commitment_pok)
                },
                "encryptedOutputBytes": hex(&result.ciphertext),
                "externalDataHashBytes": hex(&result.external_data_hash),
                "inputProofs": proofs.iter().map(|proof| json!({
                    "nullifierLeafBytes": hex(&proof.nullifier.leaf),
                    "nullifierRootIndex": proof.nullifier.root_index.to_string(),
                    "stateLeafBytes": hex(&proof.state.leaf),
                    "stateRootIndex": proof.state.root_index.to_string()
                })).collect::<Vec<_>>(),
                "nullifierBytes": result.nullifiers.iter().map(|value| hex(value)).collect::<Vec<_>>(),
                "outputHashBytes": hex(&result.output_hash),
                "privateTxHashBytes": hex(&result.private_tx_hash),
                "proverRequest": prover_request,
                "publicInputHashBytes": hex(&result.public_input_hash),
                "txViewingPubkeyBytes": hex(result.tx_viewing_pk.as_bytes())
            },
            "submission": {
                "computeUnitLimit": "1400000",
                "instruction": instruction_json(&merge_instruction),
                "submittedOutputHashBytes": hex(&result.output_hash),
                "submittedSignature": Signature::default().to_string(),
                "transaction": transaction_json(&transaction)
            },
            "stateTransition": {
                "mergedOutputAmount": "80",
                "mergedOutputCount": "1",
                "repeatedSyncAddsHistory": "0",
                "repeatedSyncAddsUtxos": "0",
                "spentInputHashBytes": real_inputs.iter().map(|input| hex(&input.hash().expect("input hash"))).collect::<Vec<_>>()
            },
            "typedErrors": [
                error(&disabled_error),
                error(&tree_error),
                error(&duplicate_error)
            ]
        }),
    ))
}

fn submit_vectors(owner: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let material = zolana_wallet::actions::submit::MergeMaterial::from_keypair(owner);
    let disabled = ClientError::MergeDisabled {
        owner: Pubkey::new_from_array([37; 32]),
    };
    let mismatch = ClientError::MergeTreeMismatch {
        proof_tree: [38; 32],
        submit_tree: [39; 32],
    };
    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED)
        }),
        json!({
            "material": {
                "signingPubkeyBytes": hex(material.signing_pubkey.as_bytes()),
                "viewingPubkeyBytes": hex(material.viewing_pubkey.as_bytes()),
                "nullifierPubkeyBytes": hex(&material.nullifier_key.pubkey()?)
            },
            "pipeline": ["validateRegistry", "fetchSpendProofs", "proveMerge", "buildMergeTransact", "submit"],
            "computeUnitLimit": "1400000",
            "errors": [error(&disabled), error(&mismatch)]
        }),
    ))
}

fn lib_vectors() -> Value {
    section(
        json!({}),
        json!({
            "modules": ["actions", "user_registry", "wallet_authority", "wallet_sync"],
            "flow": ["sync_wallet", "create_transfer", "sign_private_transaction", "send_transaction", "confirm_private_transaction"],
            "nestedErrors": {
                "client": error(&ClientError::Transaction(TransactionError::NoInputs)),
                "transaction": error(&TransactionError::NoInputs)
            }
        }),
    )
}

fn record(
    owner: Pubkey,
    bump: u8,
    keypair: &ShieldedKeypair,
    merging_enabled: bool,
) -> Result<UserRecord, Box<dyn std::error::Error>> {
    Ok(UserRecord {
        owner,
        bump,
        owner_p256: Some(*keypair.signing_pubkey().as_p256()?.as_bytes()),
        nullifier_pubkey: keypair.nullifier_key.pubkey()?,
        viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
        sync_delegate: None,
        entries: Vec::new(),
        merging_enabled,
    })
}

fn account(record: &UserRecord) -> Account {
    let mut data = vec![UserRecord::DISCRIMINATOR];
    data.extend_from_slice(&to_vec(record).expect("serialize user record"));
    Account {
        lamports: 1,
        data,
        owner: user_registry_program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn user_registry_vectors(
    owner_keypair: &ShieldedKeypair,
    rotated: &ShieldedKeypair,
) -> Result<Value, Box<dyn std::error::Error>> {
    let owner = Pubkey::new_from_array([40; 32]);
    let (pda, bump) = user_record_pda(&owner);
    let current = record(owner, bump, owner_keypair, false)?;
    let blockhash = Hash::new_from_array([41; 32]);
    let absent = build_registration_transaction_sync(
        &MockRpc {
            blockhash,
            ..Default::default()
        },
        owner,
        &owner_keypair.shielded_address()?,
    )?
    .expect("registration required");
    let noop = build_registration_transaction_sync(
        &MockRpc {
            account: Some((Address::new_from_array(pda.to_bytes()), account(&current))),
            blockhash,
            ..Default::default()
        },
        owner,
        &owner_keypair.shielded_address()?,
    )?;
    let rotation = build_registration_transaction_sync(
        &MockRpc {
            account: Some((Address::new_from_array(pda.to_bytes()), account(&current))),
            blockhash,
            ..Default::default()
        },
        owner,
        &rotated.shielded_address()?,
    )?
    .expect("rotation required");
    let resolved = resolved_address_from_record(owner, &current)?;
    let zero_tag = recipient_confidential_view_tag_sync(&MockRpc::default(), owner)?;
    Ok(section(
        json!({
            "ownerSigningSecretBytes": hex(&SIGNING_SECRET),
            "ownerViewingSeedBytes": hex(&VIEWING_SEED),
            "rotatedSigningSecretBytes": hex(&RECIPIENT_SECRET),
            "owner": owner.to_string()
        }),
        json!({
            "recordPda": pda.to_string(),
            "canonicalBump": bump.to_string(),
            "register": {
                "tag": absent.message.instructions[0].data[0].to_string(),
                "expectedTag": discriminator::REGISTER.to_string(),
                "unsignedTransaction": transaction_json(&absent)
            },
            "current": {"transaction": noop.map(|value| transaction_json(&value))},
            "rotation": {
                "tag": rotation.message.instructions[0].data[0].to_string(),
                "expectedTag": discriminator::UPDATE_KEYS.to_string(),
                "unsignedTransaction": transaction_json(&rotation)
            },
            "resolved": {
                "signingPubkeyBytes": hex(resolved.address.signing_pubkey.as_bytes()),
                "nullifierPubkeyBytes": hex(&resolved.address.nullifier_pubkey),
                "viewingPubkeyBytes": hex(resolved.address.viewing_pubkey.as_bytes()),
                "viewTagBytes": hex(&resolved.view_tag)
            },
            "publicFallbackViewTagBytes": hex(&zero_tag)
        }),
    ))
}

struct RejectingAuthority<'a> {
    local: LocalWalletAuthority<'a>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl SyncWalletAuthority for RejectingAuthority<'_> {
    fn solana_pubkey(&self) -> Address {
        SyncWalletAuthority::solana_pubkey(&self.local)
    }

    fn shielded_address(&self) -> Result<zolana_keypair::ShieldedAddress, TransactionError> {
        SyncWalletAuthority::shielded_address(&self.local)
    }

    fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError> {
        SyncWalletAuthority::viewing_keys(&self.local)
    }

    fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> Result<EncryptedTransfer, TransactionError> {
        self.calls.lock().expect("calls").push("encrypt");
        SyncWalletAuthority::encrypt_confidential_transfer(
            &self.local,
            first_nullifier,
            outputs,
            assets,
        )
    }

    fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: [u8; 32],
        sender: &zolana_transaction::serialization::anonymous::AnonymousTransferSenderPlaintext,
        recipients: &[zolana_transaction::AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_anonymous_transfer(
            &self.local,
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        view_tag: [u8; 32],
        bundle: &SplitBundlePlaintext,
    ) -> Result<EncryptedSplit, TransactionError> {
        SyncWalletAuthority::encrypt_split(&self.local, first_nullifier, view_tag, bundle)
    }

    fn request_user_approval(&self, _request: ApprovalRequest) -> Result<(), TransactionError> {
        self.calls.lock().expect("calls").push("approve");
        Err(TransactionError::Authority("approval rejected".into()))
    }

    fn sign_p256(
        &self,
        message_hash: &[u8; 32],
    ) -> Result<zolana_transaction::P256Signature, TransactionError> {
        self.calls.lock().expect("calls").push("p256Sign");
        SyncWalletAuthority::sign_p256(&self.local, message_hash)
    }

    fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError> {
        SyncWalletAuthority::spend_nullifier_key(&self.local)
    }
}

fn authority_vectors(owner: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let solana = Address::new_from_array([42; 32]);
    let local = LocalWalletAuthority::new(solana, owner);
    let material = SyncWalletAuthority::sync_material(&local)?;
    let message_hash = [43; 32];
    let signature = SyncWalletAuthority::sign_p256(&local, &message_hash)?;
    let wallet = wallet_with_amounts(owner, &[100])?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let rejecting = RejectingAuthority {
        local: LocalWalletAuthority::new(solana, owner),
        calls: calls.clone(),
    };
    let rejected = match sign_shielded_transaction_sync(
        create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: solana,
            recipient: Pubkey::new_from_array([44; 32]),
            asset: SOL_MINT,
            amount: 40,
        })?
        .transaction,
        &wallet,
        &rejecting,
    ) {
        Ok(_) => panic!("approval rejection accepted"),
        Err(error) => error,
    };
    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "messageHashBytes": hex(&message_hash)
        }),
        json!({
            "syncMaterial": {
                "identitySigningPubkeyBytes": hex(material.identity.signing_pubkey.as_bytes()),
                "viewingKeyCount": material.viewing_keys.len().to_string(),
                "nullifierPubkeyBytes": hex(&material.nullifier_key.pubkey()?)
            },
            "p256Signature": {
                "pubkeyBytes": hex(signature.pubkey.as_bytes()),
                "rBytes": hex(&signature.sig_r),
                "sBytes": hex(&signature.sig_s)
            },
            "approvalRejection": {
                "calls": calls.lock().expect("calls").clone(),
                "error": error(&rejected),
                "p256SignSkipped": !calls.lock().expect("calls").contains(&"p256Sign")
            }
        }),
    ))
}

struct FailingIndexer;

impl Rpc for FailingIndexer {
    fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<zolana_client::retry::IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Err(ClientError::IndexerTimeout)
    }
}

fn wallet_sync_vectors(owner: &ShieldedKeypair) -> Result<Value, Box<dyn std::error::Error>> {
    let authority = LocalWalletAuthority::new(Address::new_from_array([45; 32]), owner);
    let mut wallet = wallet_with_amounts(owner, &[40, 70])?;
    wallet.utxos[1].spent = true;
    let before = (
        wallet.utxos.clone(),
        wallet.transactions.clone(),
        wallet.last_synced,
        wallet.viewing_key_history.len(),
    );
    let config = SyncWalletConfig {
        tag_window: 3,
        tag_query_chunk: 2,
        page_limit: 5,
        rounds: 2,
        wait_for_indexer: true,
        retry: IndexerPollConfig::new(2, 3, 5),
    };
    let sync_error = sync_wallet_with_config(&mut wallet, &authority, &FailingIndexer, config)
        .expect_err("indexer timeout");
    let balances = get_private_token_balances(&wallet)?;
    let lag = ClientError::IndexerNotCaughtUp {
        target: 100,
        latest: 99,
        attempts: 3,
    };
    let timeout = ClientError::PollTimedOut {
        attempts: 3,
        last_cause: Some(zolana_client::RetryErrorCause::IndexerTimeout),
    };
    Ok(section(
        json!({
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "config": {
                "tagWindow": config.tag_window.to_string(),
                "tagQueryChunk": config.tag_query_chunk.to_string(),
                "pageLimit": config.page_limit.to_string(),
                "rounds": config.rounds.to_string(),
                "waitForIndexer": config.wait_for_indexer
            }
        }),
        json!({
            "atomicFailure": {
                "error": error(&sync_error),
                "walletUnchanged": wallet.utxos == before.0
                    && wallet.transactions == before.1
                    && wallet.last_synced == before.2
                    && wallet.viewing_key_history.len() == before.3
            },
            "idempotentEmptySync": {
                "durableUtxoCount": wallet.utxos.len().to_string(),
                "historyCount": get_private_transactions(&wallet).len().to_string()
            },
            "balances": balances.iter().map(|balance| json!({
                "assetId": balance.asset_id.to_string(),
                "mintBytes": hex(balance.mint.as_array()),
                "amount": balance.amount.to_string(),
                "utxoCount": balance.utxos.len().to_string()
            })).collect::<Vec<_>>(),
            "indexerOutcomes": {
                "lag": error(&lag),
                "abort": error(&sync_error),
                "timeout": error(&timeout)
            },
            "supportedShapeCount": SPP_SUPPORTED_SHAPES.len().to_string()
        }),
    ))
}
