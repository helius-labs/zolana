//! Batch settlement through `spp-batch-program`: one SPP `transact` that pays
//! every output recorded in a batch account, with real Groth16 proofs.
//!
//! The batch program is a test fixture. It stores `(nullifier_hash,
//! tree_index)` input records and `(utxo_hash, owner)` output records written
//! over several transactions and splices them into the `transact` instruction
//! data it CPIs to SPP, the outputs as inline outputs without ciphertext.

use std::time::Instant;

use anyhow::{anyhow, bail, ensure, Result};
use num_bigint::BigUint;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v1, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spp_batch_program::{
    batch_account_size, CLOSE_BATCH, HEADER_LEN, INIT_BATCH, INPUT_RECORD_LEN, RECORD_LEN, SETTLE,
    SETTLE_RING, TRANSACT_OUTPUT_LEN, WRITE_BATCH, WRITE_INPUTS, WRITE_OUTPUTS,
};
use zolana_client::{
    sign_transaction, transaction_size, ComputeBudgetConfig, ProverClient, ProverExt, PublicInputs,
    PublicTransfers, TransactionSize,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, OwnerTag},
        tag, TransactIxData,
    },
    shape::Shape,
    state::cache::empty_cached_input_fields,
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{pubkey::PublicKey, NullifierKey};
use zolana_program::instruction::Transact;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::{
    prover::spawn_workspace_prover,
    transact::{
        build_transfer_prover_inputs, compact_input, derive_test_transfer_output_blindings,
        dummy_input, external_data_hash, fe, inline_outputs, input_utxo, new_transact_ix_data,
        nullifier_tree, output_owner_pk_hashes, pack_transact_proof, real_output,
        set_output_owner_tags, single_tree_slots, sol_public_slots, test_private_tx_blinding,
        transfer_output, TransferProverInputsArgs, TEST_BLINDING_SEED,
    },
};
use zolana_transaction::{instructions::transact::PrivateTxHash, Mint, SppProofOutputUtxo};

use super::transact::tree_roots;

pub const BATCH_PROGRAM_ID: Pubkey = Pubkey::new_from_array(spp_batch_program::PROGRAM_ID);

pub const BATCH_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/spp_batch_program.so"
);

/// The largest heap a v1 transaction header can request.
pub const MAX_HEAP_BYTES: u32 = 256 * 1024;

pub const MAX_COMPUTE_UNITS: u32 = 1_400_000;

pub fn load_batch_program(pt: &mut ZolanaProgramTest) -> Result<()> {
    let elf = std::fs::read(BATCH_PROGRAM_PATH)
        .map_err(|error| anyhow!("read {BATCH_PROGRAM_PATH}: {error}; build spp-batch-program"))?;
    pt.svm
        .add_program(BATCH_PROGRAM_ID, &elf)
        .map_err(|error| anyhow!("load batch program: {error:?}"))
}

pub fn batch_address(authority: &Pubkey, batch_id: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[
            spp_batch_program::BATCH_SEED,
            authority.as_ref(),
            &batch_id.to_le_bytes(),
        ],
        &BATCH_PROGRAM_ID,
    )
    .0
}

pub struct InitBatch {
    pub payer: Pubkey,
    pub authority: Pubkey,
    pub batch_id: u64,
    pub capacity: u16,
    pub input_capacity: u8,
}

impl InitBatch {
    pub fn instruction(&self) -> Instruction {
        let mut data = vec![INIT_BATCH];
        data.extend_from_slice(&self.batch_id.to_le_bytes());
        data.extend_from_slice(&self.capacity.to_le_bytes());
        data.push(self.input_capacity);
        Instruction {
            program_id: BATCH_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(batch_address(&self.authority, self.batch_id), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
            data,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Outputs,
    Inputs,
}

impl RecordKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Outputs => WRITE_OUTPUTS,
            Self::Inputs => WRITE_INPUTS,
        }
    }
}

/// Writes `records` (concatenated records of `kind`) starting at record index
/// `offset`.
pub struct WriteBatch<'a> {
    pub authority: Pubkey,
    pub batch: Pubkey,
    pub kind: RecordKind,
    pub offset: u16,
    pub records: &'a [u8],
}

impl WriteBatch<'_> {
    pub fn instruction(&self) -> Instruction {
        let mut data = Vec::with_capacity(4 + self.records.len());
        data.push(WRITE_BATCH);
        data.push(self.kind.tag());
        data.extend_from_slice(&self.offset.to_le_bytes());
        data.extend_from_slice(self.records);
        Instruction {
            program_id: BATCH_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(self.batch, false),
            ],
            data,
        }
    }
}

pub struct SettleBatch<'a> {
    pub authority: Pubkey,
    pub batch: Pubkey,
    /// The SPP `transact` or `ring_transact` instruction the settlement CPIs;
    /// only its accounts and tag are used, its data is rebuilt by the batch
    /// program. A `ring_transact` settles with the batch program signing as
    /// the ring program.
    pub transact: &'a Instruction,
    pub split: &'a SplitTransact,
}

impl SettleBatch<'_> {
    pub fn instruction(&self) -> Result<Instruction> {
        let split = self.split;
        let ring = self.transact.data.first() == Some(&tag::RING_TRANSACT);
        let mut data =
            Vec::with_capacity(5 + split.prefix.len() + split.middle.len() + split.suffix.len());
        data.push(if ring { SETTLE_RING } else { SETTLE });
        data.extend_from_slice(&u16::try_from(split.prefix.len())?.to_le_bytes());
        data.extend_from_slice(&split.prefix);
        data.extend_from_slice(&u16::try_from(split.middle.len())?.to_le_bytes());
        data.extend_from_slice(&split.middle);
        data.extend_from_slice(&split.suffix);
        let mut accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(self.batch, false),
            AccountMeta::new_readonly(self.transact.program_id, false),
        ];
        accounts.extend(self.transact.accounts.iter().cloned());
        Ok(Instruction {
            program_id: BATCH_PROGRAM_ID,
            accounts,
            data,
        })
    }
}

pub struct CloseBatch {
    pub authority: Pubkey,
    pub batch: Pubkey,
    pub rent_recipient: Pubkey,
}

impl CloseBatch {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: BATCH_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(self.batch, false),
                AccountMeta::new(self.rent_recipient, false),
            ],
            data: vec![CLOSE_BATCH],
        }
    }
}

/// A serialized `TransactIxData` (without its tag) cut around its output
/// vector and its input vector, plus the outputs and inputs as batch records.
pub struct SplitTransact {
    pub prefix: Vec<u8>,
    pub middle: Vec<u8>,
    pub suffix: Vec<u8>,
    pub records: Vec<[u8; RECORD_LEN]>,
    pub input_records: Vec<[u8; INPUT_RECORD_LEN]>,
}

impl SplitTransact {
    pub fn new(data: &TransactIxData) -> Result<Self> {
        let records = data
            .outputs
            .iter()
            .map(|output| match (&output.owner_tag, &output.data) {
                (OwnerTag::Inline(owner), None) => {
                    let mut record = [0u8; RECORD_LEN];
                    let (hash, tag) = record.split_at_mut(32);
                    hash.copy_from_slice(&output.utxo_hash);
                    tag.copy_from_slice(owner);
                    Ok(record)
                }
                _ => bail!("batch records hold inline outputs without ciphertext"),
            })
            .collect::<Result<Vec<_>>>()?;
        let input_records = data
            .inputs
            .iter()
            .map(|input| {
                let mut record = [0u8; INPUT_RECORD_LEN];
                let (hash, tree_index) = record.split_at_mut(32);
                hash.copy_from_slice(&input.nullifier_hash);
                tree_index.copy_from_slice(&[input.tree_index]);
                record
            })
            .collect();
        let full = data.serialize()?;
        let mut without_outputs = data.clone();
        without_outputs.outputs.clear();
        let no_outputs = without_outputs.serialize()?;
        let split_at = full
            .iter()
            .zip(no_outputs.iter())
            .position(|(a, b)| a != b)
            .ok_or_else(|| anyhow!("output vector not found"))?;
        without_outputs.inputs.clear();
        let empty = without_outputs.serialize()?;
        let suffix_len = 1 + 4 * data.tree_contexts.len();
        let input_count_at = empty
            .len()
            .checked_sub(suffix_len + 1)
            .ok_or_else(|| anyhow!("input vector not found"))?;
        let section = |range: std::ops::Range<usize>| {
            empty
                .get(range)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| anyhow!("transact data section"))
        };
        let split = Self {
            prefix: section(0..split_at)?,
            middle: section(split_at + 1..input_count_at)?,
            suffix: section(input_count_at + 1..empty.len())?,
            records,
            input_records,
        };
        ensure!(
            split.transact_data()? == full,
            "batch splice does not reproduce the transact data"
        );
        Ok(split)
    }

    /// The `transact` data (without tag) the batch program assembles.
    pub fn transact_data(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.prefix);
        data.push(u8::try_from(self.records.len())?);
        for record in &self.records {
            let (hash, owner) = record.split_at(32);
            data.extend_from_slice(hash);
            data.push(0);
            data.extend_from_slice(owner);
            data.push(0);
        }
        data.extend_from_slice(&self.middle);
        data.push(u8::try_from(self.input_records.len())?);
        for record in &self.input_records {
            data.extend_from_slice(record);
        }
        data.extend_from_slice(&self.suffix);
        Ok(data)
    }

    /// Length of the tagged `transact` instruction data of the CPI.
    pub fn cpi_data_len(&self) -> usize {
        1 + self.prefix.len()
            + 1
            + TRANSACT_OUTPUT_LEN * self.records.len()
            + self.middle.len()
            + 1
            + INPUT_RECORD_LEN * self.input_records.len()
            + self.suffix.len()
    }
}

/// v1 size of `instructions` sent by `payer` with the given heap request.
pub fn v1_size(
    payer: &Pubkey,
    instructions: &[Instruction],
    heap_bytes: Option<u32>,
) -> Result<TransactionSize> {
    let budget = ComputeBudgetConfig::new(MAX_COMPUTE_UNITS);
    let Some(heap) = heap_bytes else {
        return Ok(transaction_size(payer, instructions, budget)?);
    };
    let message = v1::Message::try_compile_with_config(
        payer,
        instructions,
        Hash::default(),
        budget.transaction_config().with_heap_size(heap),
    )
    .map_err(|error| anyhow!("compile v1 message: {error}"))?;
    let signatures = usize::from(message.header.num_required_signatures);
    Ok(TransactionSize {
        bytes: signatures * 64 + 1 + message.size(),
        addresses: message.account_keys.len(),
    })
}

/// Send `instructions` as one v1 transaction signed by `payer`, with the
/// given heap request.
pub fn send_v1(
    pt: &mut ZolanaProgramTest,
    payer: &Keypair,
    instructions: &[Instruction],
    heap_bytes: Option<u32>,
) -> Result<u64> {
    Ok(send_v1_traced(pt, payer, instructions, heap_bytes)?.compute_units)
}

pub struct SentTransaction {
    pub compute_units: u64,
    /// Instruction-trace entries: every top-level and every inner (CPI)
    /// instruction, the count the runtime caps at 64.
    pub trace_entries: usize,
}

pub fn send_v1_traced(
    pt: &mut ZolanaProgramTest,
    payer: &Keypair,
    instructions: &[Instruction],
    heap_bytes: Option<u32>,
) -> Result<SentTransaction> {
    let mut config = ComputeBudgetConfig::new(MAX_COMPUTE_UNITS).transaction_config();
    if let Some(heap) = heap_bytes {
        config = config.with_heap_size(heap);
    }
    let message = v1::Message::try_compile_with_config(
        &payer.pubkey(),
        instructions,
        pt.svm.latest_blockhash(),
        config,
    )
    .map_err(|error| anyhow!("compile v1 message: {error}"))?;
    let tx = sign_transaction(VersionedMessage::V1(message), &[payer])?;
    let meta = pt
        .svm
        .send_transaction(tx)
        .map_err(|failure| anyhow!("{:?}\n{}", failure.err, failure.meta.logs.join("\n")))?;
    pt.svm.expire_blockhash();
    Ok(SentTransaction {
        compute_units: meta.compute_units_consumed,
        trace_entries: instructions.len()
            + meta.inner_instructions.iter().map(Vec::len).sum::<usize>(),
    })
}

pub struct BatchFill {
    pub batch: Pubkey,
    pub write_transactions: usize,
    pub account_bytes: usize,
}

/// One `WriteBatch` per record kind present in `records`, in order.
fn write_instructions(
    authority: &Pubkey,
    batch: &Pubkey,
    records: &[(RecordKind, u16, &[u8])],
) -> Vec<Instruction> {
    let mut runs: Vec<(RecordKind, u16, Vec<u8>)> = Vec::new();
    for (kind, index, record) in records {
        match runs.last_mut() {
            Some((run_kind, _, bytes)) if run_kind == kind => bytes.extend_from_slice(record),
            _ => runs.push((*kind, *index, record.to_vec())),
        }
    }
    runs.iter()
        .map(|(kind, offset, bytes)| {
            WriteBatch {
                authority: *authority,
                batch: *batch,
                kind: *kind,
                offset: *offset,
                records: bytes,
            }
            .instruction()
        })
        .collect()
}

/// Create the batch account and fill it with the split's input and output
/// records, inputs first. Each write transaction packs as many records as
/// fit in 4,096 bytes (and at most `max_records_per_write`), switching from
/// the input to the output kind inside one transaction when there is room.
pub fn fill_batch(
    pt: &mut ZolanaProgramTest,
    authority: &Keypair,
    batch_id: u64,
    split: &SplitTransact,
    max_records_per_write: usize,
) -> Result<BatchFill> {
    let init = InitBatch {
        payer: authority.pubkey(),
        authority: authority.pubkey(),
        batch_id,
        capacity: u16::try_from(split.records.len())?,
        input_capacity: u8::try_from(split.input_records.len())?,
    };
    send_v1(pt, authority, &[init.instruction()], None)?;
    let batch = batch_address(&authority.pubkey(), batch_id);
    let all: Vec<(RecordKind, u16, &[u8])> = split
        .input_records
        .iter()
        .enumerate()
        .map(|(index, record)| Ok((RecordKind::Inputs, u16::try_from(index)?, record.as_slice())))
        .chain(split.records.iter().enumerate().map(|(index, record)| {
            Ok((
                RecordKind::Outputs,
                u16::try_from(index)?,
                record.as_slice(),
            ))
        }))
        .collect::<Result<_>>()?;
    let mut write_transactions = 0;
    let mut start = 0;
    while start < all.len() {
        let mut end = start + 1;
        let fits = |end: usize| -> Result<bool> {
            let chunk = all.get(start..end).ok_or_else(|| anyhow!("record range"))?;
            let ixs = write_instructions(&authority.pubkey(), &batch, chunk);
            Ok(v1_size(&authority.pubkey(), &ixs, None)?.fits())
        };
        ensure!(fits(end)?, "no record fits a write transaction");
        while end < all.len() && end - start < max_records_per_write && fits(end + 1)? {
            end += 1;
        }
        let chunk = all.get(start..end).ok_or_else(|| anyhow!("record range"))?;
        let ixs = write_instructions(&authority.pubkey(), &batch, chunk);
        send_v1(pt, authority, &ixs, None)?;
        write_transactions += 1;
        start = end;
    }
    let account = pt
        .svm
        .get_account(&batch)
        .ok_or_else(|| anyhow!("batch account missing"))?;
    ensure!(
        account.data.len() == batch_account_size(split.records.len(), split.input_records.len()),
        "batch account size"
    );
    let mut expected = Vec::new();
    for record in &split.input_records {
        expected.extend_from_slice(record);
    }
    for record in &split.records {
        expected.extend_from_slice(record);
    }
    ensure!(
        account.data.get(HEADER_LEN..) == Some(expected.as_slice()),
        "batch account holds the written records"
    );
    Ok(BatchFill {
        batch,
        write_transactions,
        account_bytes: account.data.len(),
    })
}

pub struct ProofTiming {
    pub first_secs: f64,
    pub second_secs: f64,
}

/// Run `prove` twice, the first call loading the proving key, and time both.
pub fn prove_twice<T, E: std::fmt::Display>(
    label: &str,
    mut prove: impl FnMut() -> std::result::Result<T, E>,
) -> Result<(T, ProofTiming)> {
    let start = Instant::now();
    let proof = prove().map_err(|error| anyhow!("prove {label}: {error}"))?;
    let first_secs = start.elapsed().as_secs_f64();
    let start = Instant::now();
    prove().map_err(|error| anyhow!("prove {label} again: {error}"))?;
    let second_secs = start.elapsed().as_secs_f64();
    Ok((
        proof,
        ProofTiming {
            first_secs,
            second_secs,
        },
    ))
}

/// A transact spending `sent_inputs` dummy inputs into `sent_outputs`
/// zero-amount outputs, each to a distinct owner, so the program hashes one
/// owner identity per output, at the `n_inputs x n_outputs` shape. Input and
/// output slots past the sent counts are compact padding, which the
/// instruction leaves out.
/// Without `prove`, the proof stays zeroed (for probes that fail before
/// verification).
pub struct ScalingSpend {
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub sent_inputs: usize,
    pub sent_outputs: usize,
    pub prove: bool,
}

pub struct ProvenSpend {
    pub data: TransactIxData,
    pub timing: Option<ProofTiming>,
}

impl ScalingSpend {
    pub fn build(&self, pt: &ZolanaProgramTest, tree: Pubkey, tree_id: u16) -> Result<ProvenSpend> {
        let (n_inputs, n_outputs) = (self.n_inputs, self.n_outputs);
        let sent_outputs = self.sent_outputs;
        ensure!(sent_outputs <= n_outputs, "more sent outputs than slots");
        let sent_inputs = self.sent_inputs;
        ensure!(
            (1..=n_inputs).contains(&sent_inputs),
            "sent inputs out of range"
        );
        let payer_bytes = pt.payer.pubkey().to_bytes();
        let (utxo_root, nullifier_root) = tree_roots(pt, &tree, 0);
        let tree_slots = single_tree_slots(tree_id, utxo_root, nullifier_root);
        let zero = [0u8; 32];

        let nf_tree = nullifier_tree()?;
        let mut inputs = Vec::with_capacity(n_inputs);
        let mut nullifiers = Vec::with_capacity(n_inputs);
        for index in 0..sent_inputs {
            let (input, nullifier) =
                dummy_input(&[u8::try_from(index + 31)?; 31], &nf_tree, tree_id)?;
            inputs.push(input);
            nullifiers.push(nullifier);
        }
        for _ in sent_inputs..n_inputs {
            inputs.push(compact_input(&nf_tree, tree_id)?);
        }
        let mut padded_nullifiers = nullifiers.clone();
        padded_nullifiers.resize(n_inputs, zero);

        let nullifier_key = NullifierKey::from_secret([21u8; 31]);
        let nullifier_pk = nullifier_key.pubkey()?;
        let mut outputs = Vec::with_capacity(n_outputs);
        let mut view_tags = Vec::with_capacity(sent_outputs);
        for _ in 0..sent_outputs {
            let owner = PublicKey::from_ed25519(&Keypair::new().pubkey().to_bytes());
            view_tags.push(owner.confidential_view_tag()?);
            let real = real_output(owner, nullifier_pk, Mint::SOL, 0, [23u8; 31]);
            outputs.push(transfer_output(&real, tree_id)?);
        }
        let first_nullifier = *nullifiers
            .first()
            .ok_or_else(|| anyhow!("a spend has an input"))?;
        let compact = SppProofOutputUtxo {
            compact: true,
            ..Default::default()
        };
        for _ in sent_outputs..n_outputs {
            let mut output = transfer_output(&compact, tree_id)?;
            output.is_dummy = BigUint::from(1u8);
            outputs.push(output);
        }
        let mut output_hashes =
            derive_test_transfer_output_blindings(&first_nullifier, &mut outputs)?;
        for (output, hash) in outputs
            .iter_mut()
            .zip(output_hashes.iter_mut())
            .skip(sent_outputs)
        {
            output.hash = BigUint::ZERO;
            *hash = zero;
        }
        let sent_hashes = output_hashes
            .get(..sent_outputs)
            .ok_or_else(|| anyhow!("sent output hashes"))?
            .to_vec();

        let mut data = new_transact_ix_data(
            nullifiers
                .iter()
                .map(|nullifier| input_utxo(*nullifier))
                .collect(),
            0,
            Vec::new(),
            inline_outputs(&sent_hashes, &view_tags),
        );
        data.circuit = CircuitId::ConfidentialEddsa(
            u8::try_from(n_inputs)?,
            u8::try_from(n_outputs)?,
            N_PUBLIC_SLOTS as u8,
        );
        if !self.prove {
            return Ok(ProvenSpend { data, timing: None });
        }

        let mut owner_pk_hashes = output_owner_pk_hashes(&data.outputs)?;
        set_output_owner_tags(
            &mut outputs,
            &owner_pk_hashes,
            &vec![nullifier_pk; sent_outputs],
        );
        owner_pk_hashes.resize(n_outputs, zero);
        let external_data_hash = external_data_hash(&data, &[])?;
        let private_tx_blinding = test_private_tx_blinding(&first_nullifier)?;
        let private_tx =
            PrivateTxHash::new(&vec![zero; n_inputs], &output_hashes, &private_tx_blinding)
                .hash()?;
        let mut signer_pk_hashes = vec![zero; Shape::new(n_inputs, n_outputs).signer_width()];
        if let Some(first) = signer_pk_hashes.first_mut() {
            *first = solana_owner_identity(&payer_bytes)?;
        }
        let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
        let public_input_hash = PublicInputs {
            nullifiers: &padded_nullifiers,
            output_hashes: &output_hashes,
            tree_slots: &tree_slots,
            output_tree_id: tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &PublicTransfers {
                assets: public_slot_assets,
                amounts: public_slot_amounts,
            },
            ring_program_id: &zero,
            input_flags: &fe(1),
            signer_pk_hashes: &signer_pk_hashes,
            output_owner_pk_hashes: Some(&owner_pk_hashes),
            cached_inputs: empty_cached_input_fields(n_inputs)?,
        }
        .hash()?;
        let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
            inputs,
            outputs,
            tree_slots,
            output_tree_id: tree_id,
            blinding_seed: TEST_BLINDING_SEED,
            external_data_hash,
            private_tx_hash: private_tx,
            public_slot_assets,
            public_slot_amounts,
            signer_pk_hashes,
            public_input_hash,
        });
        spawn_workspace_prover(zolana_client::IndexerRequirement::Optional);
        let prover = ProverClient::local();
        let (proof, timing) = prove_twice(&format!("{n_inputs}x{n_outputs}"), || {
            prover.prove_transfer(&prover_inputs)
        })?;
        data.proof = pack_transact_proof(&proof)?;
        data.private_tx_hash = private_tx;
        Ok(ProvenSpend {
            data,
            timing: Some(timing),
        })
    }
}

/// The SPP `transact` instruction for a spend from and into `tree`.
pub fn transact_instruction(payer: Pubkey, tree: Pubkey, data: TransactIxData) -> Instruction {
    Transact {
        payer,
        input_trees: vec![tree],
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction()
}
