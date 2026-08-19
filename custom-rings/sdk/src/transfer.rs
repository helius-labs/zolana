//! The audited ring transfer as a client builds it: ring deposits for the
//! sender, then a confidential transfer whose auditor message is proven against
//! the ring's auditor key.
//!
//! The order inside [`AuditedTransfer::prove`] is load bearing. The auditor
//! message must be inside `external_data` before the SPP proof runs, because
//! SPP folds `messages` into `external_data_hash` and that into
//! `private_tx_hash`, which is the first element of the audit circuit's public
//! input chain. `AuditProofParams::encrypt` returns a `PendingAuditProof` that
//! only `finish(private_tx_hash)` turns into a proof input, which is what keeps
//! the order.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    ProofCompressed, ProverClient, RingTransferProofResult, RingTransferProver, Rpc, Shape,
    SpendProof, SppProofInputUtxo, SppProofInputs, TransferSpendInput,
};
use zolana_interface::{
    instruction::{
        tag::RING_TRANSACT, CircuitId, DepositAsset, InputUtxo, RingAssetDeposit,
        TransactInterfaceTransferAccounts, TransactIxData, TransactProof,
        TransactSolTransferAccounts,
    },
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{random_blinding, P256Pubkey, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    instructions::transact::{
        encrypt_transaction_data, get_transaction_viewing_key, ExternalData, SettlementTransfer,
        SppProofOutputUtxo,
    },
    owner_utxo_hash, AssetRegistry, Data, RingDepositPlaintext, Utxo, SOL_MINT,
};

use crate::{
    to_instruction_proof, AuditProof, AuditProofParams, CustomRingProverClient, Deposit,
    RingTransactWithAudit, PROGRAM_ID,
};

/// A UTXO's `data_hash` / `ring_data_hash` when it carries neither.
const ZERO: [u8; 32] = [0u8; 32];

/// One audited transfer. `sender` spends `inputs` (ring-owned UTXOs) into
/// `outputs` and `withdrawals`, and the transaction viewing key is verifiably
/// encrypted to `auditor_pk`.
pub struct AuditedTransfer<'a, I: Rpc> {
    pub indexer: &'a I,
    pub spp_prover: &'a ProverClient,
    pub sender: &'a ShieldedKeypair,
    pub inputs: Vec<Utxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// Public SOL withdrawals out of the pool, `(recipient, lamports)`.
    pub withdrawals: Vec<(Address, u64)>,
    pub tree: Address,
    pub auditor_pk: P256Pubkey,
    pub assets: &'a AssetRegistry,
}

/// Both proofs and the instruction data they verify, ready to send.
pub struct ProvenTransfer {
    /// The key the auditor recovers, every output ciphertext is under it.
    pub tx_viewing_key: ViewingKey,
    pub data: TransactIxData,
    pub audit_proof: AuditProof,
    pub owner_signers: Vec<Address>,
    /// Settlement accounts of `data.interface_transfers`, in order.
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
}

impl<I: Rpc> AuditedTransfer<'_, I> {
    pub fn prove(self) -> Result<ProvenTransfer> {
        let input_utxos: Vec<SppProofInputUtxo> = self
            .inputs
            .iter()
            .map(|utxo| SppProofInputUtxo::new(utxo.clone(), self.sender))
            .collect();
        let tx_viewing_key = get_transaction_viewing_key(self.sender, &input_utxos)?;

        let (pending_audit_proof, auditor_message) = AuditProofParams {
            tx_viewing_sk: tx_viewing_key.secret_bytes(),
            auditor_pk: self.auditor_pk,
        }
        .encrypt()?;
        let encoded = encrypt_transaction_data(&self.outputs, self.assets, &tx_viewing_key)?;
        let mut external_data = ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![auditor_message.to_message_data(&self.auditor_pk)],
        )
        .with_interface_transfers(
            self.withdrawals
                .iter()
                .map(|(recipient, amount)| SettlementTransfer::Sol {
                    is_deposit: false,
                    amount: *amount,
                    user_sol_account: *recipient,
                })
                .collect(),
        )?;
        // Folded into external_data_hash and from there into private_tx_hash,
        // so it is bound before anything hashes external data.
        external_data.instruction_discriminator = RING_TRANSACT;
        let proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            self.sender.pubkey(),
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
            ProofCompressed::try_from(self.spp_prover.prove_transfer_ring(&ring_result.inputs)?)?
                .to_transact_proof();

        let audit_inputs = pending_audit_proof.finish(&ring_result.private_tx_hash)?;
        let audit_proof = to_instruction_proof(
            &CustomRingProverClient::new().prove_auditor_key_encryption(&audit_inputs)?,
        );

        Ok(ProvenTransfer {
            tx_viewing_key,
            data: assemble_ring_eddsa_ix_data(&proof_inputs, &ring_result, spp_proof)?,
            audit_proof,
            owner_signers: proof_inputs.owner_signer_pubkeys()?,
            interface_transfer_accounts: self
                .withdrawals
                .iter()
                .map(|(recipient, _)| {
                    TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                        recipient: *recipient,
                    })
                })
                .collect(),
        })
    }
}

impl ProvenTransfer {
    /// What an approver signs off, and the seed of the approval account.
    pub fn private_tx_hash(&self) -> [u8; 32] {
        self.data.private_tx_hash
    }

    /// The audited ring transact instruction, `payer` paying. `approval` is
    /// this transact's approval account when a withdrawal falls under an
    /// approval rule. `ring_config` (the ring's `ring_auth` PDA) stays unsigned
    /// here, the program flips it to a signer inside its CPI.
    pub fn instruction(
        &self,
        payer: Address,
        tree: Address,
        approval: Option<Address>,
    ) -> Result<Instruction> {
        RingTransactWithAudit {
            payer,
            input_tree: tree,
            output_tree: tree,
            owner_signers: self.owner_signers.clone(),
            approval,
            interface_transfer_accounts: self.interface_transfer_accounts.clone(),
            audit_proof: self.audit_proof,
            transact: self.data.clone(),
        }
        .instruction()
        .map_err(|e| anyhow!("ring transact instruction: {e}"))
    }
}

/// Ring-deposit `amount` lamports to `recipient`'s shielded address, paid by
/// `payer`, returning the ring-owned UTXO the deposit created. The public face
/// of a ring deposit carries only the `owner_utxo_hash` commitment and the
/// recipient bootstrap view tag, while the blinding travels encrypted to the
/// recipient's viewing key.
pub fn ring_deposit_sol<R: Rpc>(
    rpc: &R,
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

/// The state and non-inclusion witnesses every real spend needs. The indexer
/// client polls until every requested proof is present.
pub fn ring_spend_inputs<I: Rpc>(
    indexer: &I,
    tree: Address,
    spends: &[SppProofInputUtxo],
) -> Result<Vec<TransferSpendInput>> {
    if spends.iter().any(SppProofInputUtxo::is_dummy) {
        return Err(anyhow!("the audited transfer spends real ring UTXOs only"));
    }
    let utxo_hashes = spends
        .iter()
        .map(SppProofInputUtxo::hash)
        .collect::<Result<Vec<_>, _>>()?;
    let nullifiers = spends
        .iter()
        .map(SppProofInputUtxo::nullifier)
        .collect::<Result<Vec<_>, _>>()?;
    let states = indexer.get_merkle_proofs(tree, utxo_hashes, None)?.proofs;
    let non_inclusions = indexer
        .get_non_inclusion_proofs(tree, nullifiers, None)?
        .proofs;
    if states.len() != spends.len() || non_inclusions.len() != spends.len() {
        return Err(anyhow!(
            "indexer returned {} state and {} non-inclusion proofs for {} spends",
            states.len(),
            non_inclusions.len(),
            spends.len()
        ));
    }
    Ok(spends
        .iter()
        .zip(states)
        .zip(non_inclusions)
        .map(|((spend, state), nullifier)| TransferSpendInput {
            utxo: spend.utxo.clone(),
            nullifier_key: spend.nullifier_key.clone(),
            data_hash: None,
            ring_data_hash: None,
            proof: Some(SpendProof { state, nullifier }),
            nullifier_proof: None,
        })
        .collect())
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
/// PDA) stays unsigned here, the program flips it to a signer inside its CPI.
pub fn ring_transact_ix(
    payer: Address,
    tree: Address,
    owner_signers: Vec<Address>,
    audit_proof: AuditProof,
    transact: TransactIxData,
) -> Result<Instruction> {
    RingTransactWithAudit {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers,
        approval: None,
        interface_transfer_accounts: Vec::new(),
        audit_proof,
        transact,
    }
    .instruction()
    .map_err(|e| anyhow!("ring transact instruction: {e}"))
}
