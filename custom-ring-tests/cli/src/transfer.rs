//! The audited ring transfer: two ring deposits for a fresh sender, one
//! confidential transfer to a fresh recipient carrying the auditor message and
//! its proof, then the auditor's view of it read back from the ring RPC.
//!
//! The order inside [`AuditedTransfer::run`] is load bearing. The auditor
//! message must be inside `external_data` before the SPP proof runs, because
//! SPP folds `messages` into `external_data_hash` and that into
//! `private_tx_hash`, which is the first element of the audit circuit's public
//! input chain. `AuditProofParams::encrypt` returns a `PendingAuditProof` that
//! only `finish(private_tx_hash)` turns into a proof input, which is what keeps
//! the order.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use custom_ring_sdk::{
    to_instruction_proof, AuditProof, AuditProofParams, CustomRingProverClient, Deposit,
    RingTransactWithAudit, PROGRAM_ID,
};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    ProofCompressed, ProverClient, RingTransferProofResult, RingTransferProver, Rpc, Shape,
    SolanaRpc, SpendProof, SppProofInputUtxo, SppProofInputs, TransferSpendInput, ZolanaIndexer,
};
use zolana_interface::{
    instruction::{
        tag::RING_TRANSACT, CircuitId, DepositAsset, InputUtxo, RingAssetDeposit, TransactIxData,
        TransactProof,
    },
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{random_blinding, P256Pubkey, ShieldedKeypair};
use zolana_transaction::{
    instructions::transact::{
        encrypt_transaction_data, get_transaction_viewing_key, ExternalData, SppProofOutputUtxo,
    },
    owner_utxo_hash, AssetRegistry, Data, RingDepositPlaintext, Utxo, SOL_MINT,
};

use crate::lookup_table::send_v0_with_lookup_table;

/// A UTXO's `data_hash` / `ring_data_hash` when it carries neither.
const ZERO: [u8; 32] = [0u8; 32];
/// Lamports the sender receives for its lookup table rent and fees.
const SENDER_FEE_BUDGET: u64 = 20_000_000;
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

pub struct AuditedTransfer<'a> {
    pub rpc: &'a SolanaRpc,
    pub indexer: &'a ZolanaIndexer,
    pub prover: &'a ProverClient,
    /// Pays the deposits and funds the sender for its own transaction. The
    /// sender pays and signs the transact itself: with a separate fee payer
    /// the second signature and static key push the audited transact past the
    /// 1232-byte packet even behind a lookup table.
    pub payer: &'a dyn Signer,
    pub tree: Address,
    pub auditor_pk: P256Pubkey,
    /// Lamports the recipient receives. The sender is funded with twice that
    /// through two ring deposits, so the change output is the same amount.
    pub amount: u64,
}

pub struct TransferReceipt {
    pub sender: ShieldedKeypair,
    pub recipient: ShieldedKeypair,
    pub deposits: Vec<Signature>,
    pub transact: Signature,
}

impl AuditedTransfer<'_> {
    pub fn run(self) -> Result<TransferReceipt> {
        let sender = ShieldedKeypair::new_ed25519()?;
        let recipient = ShieldedKeypair::new_ed25519()?;
        let assets = AssetRegistry::default();

        let mut spendable = Vec::with_capacity(2);
        let mut deposits = Vec::with_capacity(2);
        for _ in 0..2 {
            let (signature, utxo) =
                ring_deposit_sol(self.rpc, self.payer, &sender, self.tree, self.amount)?;
            spendable.push(utxo);
            deposits.push(signature);
        }

        fund(self.rpc, self.payer, &sender.pubkey(), SENDER_FEE_BUDGET)?;

        let input_utxos: Vec<SppProofInputUtxo> = spendable
            .iter()
            .map(|utxo| SppProofInputUtxo::new(utxo.clone(), &sender))
            .collect();
        let tx_viewing_key = get_transaction_viewing_key(&sender, &input_utxos)?;

        let change_output =
            SppProofOutputUtxo::new(SOL_MINT, self.amount, sender.shielded_address()?)?;
        let recipient_output =
            SppProofOutputUtxo::new(SOL_MINT, self.amount, recipient.shielded_address()?)?;

        let (pending_audit_proof, auditor_message) = AuditProofParams {
            tx_viewing_sk: tx_viewing_key.secret_bytes(),
            auditor_pk: self.auditor_pk,
        }
        .encrypt()?;
        let encoded =
            encrypt_transaction_data(&[change_output, recipient_output], &assets, &tx_viewing_key)?;
        let mut external_data = ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![auditor_message.to_message_data(&self.auditor_pk)],
        );
        external_data.instruction_discriminator = RING_TRANSACT;
        let proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            sender.pubkey(),
        );

        let tx_shape = proof_inputs.check_shape()?;
        let ring_result = RingTransferProver {
            inputs: ring_spend_inputs(self.indexer, self.tree, &proof_inputs.input_utxos)?,
            outputs: proof_inputs.output_utxos.clone(),
            external_data: proof_inputs.external_data.clone(),
            public_transfers: proof_inputs.public_transfers()?,
            signer_pk_hashes: proof_inputs.signer_pk_hashes(tx_shape.n_inputs() + 1)?,
            allow_dummy_inputs: true,
            ring_program_id: Some(PROGRAM_ID),
            shape: Some(Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs())),
        }
        .build()?;
        let spp_proof =
            ProofCompressed::try_from(self.prover.prove_transfer_ring(&ring_result.inputs)?)?
                .to_transact_proof();

        let audit_inputs = pending_audit_proof.finish(&ring_result.private_tx_hash)?;
        let audit_proof = to_instruction_proof(
            &CustomRingProverClient::new().prove_auditor_key_encryption(&audit_inputs)?,
        );

        let data = assemble_ring_eddsa_ix_data(&proof_inputs, &ring_result, spp_proof)?;
        let owner_signers = proof_inputs.owner_signer_pubkeys()?;
        let ix = ring_transact_ix(sender.pubkey(), self.tree, owner_signers, audit_proof, data)?;
        let transact = send_v0_with_lookup_table(self.rpc, &sender, &[], ix)?;

        Ok(TransferReceipt {
            sender,
            recipient,
            deposits,
            transact,
        })
    }
}

fn fund(rpc: &SolanaRpc, payer: &dyn Signer, to: &Address, lamports: u64) -> Result<()> {
    let ix = solana_system_interface::instruction::transfer(&payer.pubkey(), to, lamports);
    rpc.create_and_send_transaction(&[ix], payer.pubkey(), &[payer])?;
    Ok(())
}

/// Ring-deposit `amount` lamports to `recipient`'s shielded address, paid by
/// `payer`, returning the ring-owned UTXO the deposit created. The public face
/// of a ring deposit carries only the `owner_utxo_hash` commitment and the
/// recipient bootstrap view tag; the blinding travels encrypted to the
/// recipient's viewing key.
pub fn ring_deposit_sol(
    rpc: &SolanaRpc,
    payer: &dyn Signer,
    recipient: &ShieldedKeypair,
    tree: Address,
    amount: u64,
) -> Result<(Signature, Utxo)> {
    let blinding = random_blinding();
    let deposit = RingAssetDeposit {
        asset: DepositAsset::Sol,
        view_tag: recipient.recipient_bootstrap_view_tag(),
        owner_utxo_hash: owner_utxo_hash(&recipient.owner_hash()?, &blinding)?,
        amount,
        data_hash: None,
        ring_data_hash: ZERO,
        encrypted: RingDepositPlaintext {
            blinding,
            utxo_data: None,
            memo: None,
            ring_data: Vec::new(),
        }
        .encrypt(&recipient.viewing_pubkey())?,
    };
    let ix = Deposit {
        tree,
        depositor: payer.pubkey(),
        deposits: vec![deposit],
    }
    .instruction()
    .map_err(|e| anyhow!("ring deposit instruction: {e}"))?;
    let signature = rpc.create_and_send_transaction(&[ix], payer.pubkey(), &[payer])?;
    Ok((
        signature,
        Utxo {
            owner: recipient.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding,
            // A ring deposit's output is owned by the ring, which binds the ring
            // into the UTXO hash the transfer proof spends.
            ring_program_id: Some(PROGRAM_ID),
            data: Data::default(),
        },
    ))
}

/// The state and non-inclusion witnesses every real spend needs, waiting for the
/// indexer to catch up with the deposits.
pub fn ring_spend_inputs<I: Rpc>(
    indexer: &I,
    tree: Address,
    spends: &[SppProofInputUtxo],
) -> Result<Vec<TransferSpendInput>> {
    let mut inputs = Vec::with_capacity(spends.len());
    for spend in spends {
        if spend.is_dummy() {
            return Err(anyhow!("the audited transfer spends real ring UTXOs only"));
        }
        let nullifier_pk = spend.nullifier_key.pubkey()?;
        let utxo_hash = spend.utxo.hash(&nullifier_pk, &ZERO, &ZERO)?;
        let nullifier = spend
            .nullifier_key
            .nullifier(&utxo_hash, &spend.utxo.blinding)?;
        let state = wait_for("indexed merkle proof", || {
            Ok(indexer
                .get_merkle_proofs(tree, vec![utxo_hash], None)?
                .proofs
                .into_iter()
                .next())
        })?;
        let non_inclusion = wait_for("indexed non-inclusion proof", || {
            Ok(indexer
                .get_non_inclusion_proofs(tree, vec![nullifier], None)?
                .proofs
                .into_iter()
                .next())
        })?;
        inputs.push(TransferSpendInput {
            utxo: spend.utxo.clone(),
            nullifier_key: spend.nullifier_key.clone(),
            data_hash: None,
            ring_data_hash: None,
            proof: Some(SpendProof {
                state,
                nullifier: non_inclusion,
            }),
            nullifier_proof: None,
        });
    }
    Ok(inputs)
}

/// Fold the signed transaction's external data and the ring prover's result into
/// the `TransactIxData` SPP verifies, on the eddsa rail this ring supports:
/// `external_data` fields flow through unchanged (already rebound to
/// `RING_TRANSACT` and already carrying the auditor message), and authorization
/// comes from the leading signer run in the account list.
pub fn assemble_ring_eddsa_ix_data(
    proof_inputs: &SppProofInputs,
    result: &RingTransferProofResult,
    proof: TransactProof,
) -> Result<TransactIxData> {
    let n_inputs = proof_inputs.check_shape()?.n_inputs();
    let inputs: Vec<InputUtxo> = result
        .nullifiers
        .iter()
        .zip(result.input_root_indices.iter())
        .map(
            |(nullifier_hash, &(utxo_tree_root_index, nullifier_tree_root_index))| InputUtxo {
                nullifier_hash: *nullifier_hash,
                nullifier_tree_root_index,
                utxo_tree_root_index,
            },
        )
        .collect();
    if inputs.len() != n_inputs {
        return Err(anyhow!(
            "prover returned {} nullifier/root-index pairs for shape {n_inputs}",
            inputs.len()
        ));
    }

    let external = &proof_inputs.external_data;
    Ok(TransactIxData {
        proof,
        expiry_unix_ts: external.expiry_unix_ts,
        private_tx_hash: result.private_tx_hash,
        circuit: CircuitId::RingEddsa(
            n_inputs as u8,
            external.outputs.len() as u8,
            N_PUBLIC_SLOTS as u8,
        ),
        inputs,
        interface_transfers: external
            .interface_transfers
            .iter()
            .map(|transfer| transfer.interface_transfer())
            .collect(),
        data_hash: external.data_hash,
        ring_data_hash: external.ring_data_hash,
        tx_viewing_pk: external.tx_viewing_pk,
        salt: external.salt,
        outputs: external.outputs.clone(),
        messages: external.messages.clone(),
    })
}

/// The audited ring transact instruction. `ring_config` (the ring's `ring_auth`
/// PDA) stays unsigned here; the program flips it to a signer inside its CPI.
pub fn ring_transact_ix(
    payer: Address,
    tree: Address,
    owner_signers: Vec<Address>,
    audit_proof: AuditProof,
    transact: TransactIxData,
) -> Result<solana_instruction::Instruction> {
    RingTransactWithAudit {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers,
        interface_transfer_accounts: Vec::new(),
        audit_proof,
        transact,
    }
    .instruction()
    .map_err(|e| anyhow!("ring transact instruction: {e}"))
}

/// Poll `probe` until it yields a value or the indexer timeout passes.
pub fn wait_for<T>(label: &str, mut probe: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    let deadline = Instant::now() + INDEXER_TIMEOUT;
    let mut last_error = None;
    while Instant::now() < deadline {
        match probe() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(match last_error {
        Some(error) => error.context(format!("timed out waiting for {label}")),
        None => anyhow!("timed out waiting for {label}"),
    })
}

/// Block until the indexer serves `signature`.
pub fn wait_for_indexed_transaction<I: Rpc>(indexer: &I, signature: Signature) -> Result<()> {
    wait_for("indexed transaction", || {
        let response = indexer.get_shielded_transactions_by_signature(signature, None)?;
        Ok(response.transactions.into_iter().next().map(|_| ()))
    })
    .with_context(|| format!("transaction {signature}"))
}
