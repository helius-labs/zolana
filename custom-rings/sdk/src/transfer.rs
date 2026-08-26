use rand::{rngs::OsRng, RngCore};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{
    ClientError, ProofCompressed, ProverClient, RingTransferProofResult, RingTransferProver, Rpc,
    SettlementAccountValidation, Shape, SpendProof, SppProofInputUtxo, SppProofInputs,
    TransferSpendInput,
};
use zolana_interface::event::OutputDataEncoding;
use zolana_interface::{
    instruction::{
        tag::RING_TRANSACT, CircuitId, DepositAsset, DepositBuildError, InputUtxo,
        RingAssetDeposit, TransactInterfaceTransferAccounts, TransactIxData, TransactProof,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, random_salt, KeypairError, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    instructions::transact::{
        encode_confidential_slots, ChangeLayout, PreparedTransfer, SppProofOutputUtxo,
    },
    owner_utxo_hash, AssetRegistry, Data, EncryptedScheme, RingDepositPlaintext, TransactionError,
    Utxo, SOL_MINT,
};
use zolana_tree::{TreeAccount, TreeError};

use crate::{
    to_instruction_proof, AccountReadError, CustomRing, CustomRingProof, CustomRingProofError,
    CustomRingProofInputError, CustomRingProofParams, CustomRingTransact, Deposit, EncryptedAudit,
};

const NO_RING_DATA_HASH: [u8; 32] = [0u8; 32];

#[must_use = "prove or discard the transfer explicitly"]
pub struct CustomRingTransfer<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    prepared: PreparedTransfer,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    tree: Option<Address>,
    assets: Option<&'a AssetRegistry>,
}

pub struct CustomRingTransferInput<'a> {
    pub ring: CustomRing,
    pub sender: &'a ShieldedKeypair,
    pub prepared: PreparedTransfer,
}

pub struct TransferProofEnvironment<'a, I: Rpc, R: Rpc> {
    pub indexer: &'a I,
    pub rpc: &'a R,
    pub prover: &'a ProverClient,
}

#[must_use = "build or submit the proven transfer"]
pub struct ProvenTransfer {
    pub tx_viewing_key: ViewingKey,
    pub data: TransactIxData,
    pub proof: CustomRingProof,
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    /// History entries a policy statement binds, zero without rules.
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
    payer: Address,
    tree: Address,
    ring: CustomRing,
}

#[must_use]
pub struct RingDeposit<'a> {
    pub ring: CustomRing,
    pub payer: &'a dyn Signer,
    pub recipient: &'a ShieldedKeypair,
    pub tree: Address,
    pub amount: u64,
}

pub struct RingDepositReceipt {
    pub signature: Signature,
    pub utxo: Utxo,
}

#[derive(Debug, Error)]
pub enum TransferError {
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    ProofInput(#[from] CustomRingProofInputError),
    #[error(transparent)]
    Proof(#[from] CustomRingProofError),
    #[error(transparent)]
    Instruction(#[from] wincode::Error),
    #[error(transparent)]
    Encoding(#[from] std::io::Error),
    #[error("indexer returned an incomplete proof set")]
    IncompleteProofSet,
    #[error("prover returned an incomplete input set")]
    IncompleteInputSet,
    #[error("input tree account does not exist")]
    MissingTree,
    #[error("input tree owner is invalid")]
    InvalidTreeOwner,
    #[error("input tree discriminator is invalid")]
    InvalidTreeDiscriminator,
    #[error("input tree address is required")]
    TreeRequired,
    #[error("custom ring config does not exist")]
    MissingRingConfig,
    #[error("the ring has no policy config")]
    MissingPolicyConfig,
    #[error("policy hashing failed")]
    PolicyHashing,
    #[error("the transfer needs more policy slots than the circuit holds")]
    PolicyShapeUnsupported,
    #[error("a policy rule refuses the transfer")]
    PolicyRuleUnsatisfied,
    #[error("no policy source serves the record kind")]
    MissingPolicySource,
    #[error(transparent)]
    Record(Box<crate::RecordProofError>),
    #[error("transfer was prepared with padded change slots, prepare it with ConfidentialTransfer::with_compact_change")]
    PaddedChange,
    #[error("asset registry is required")]
    MissingAssetRegistry,
    #[error("dummy output framing is invalid")]
    InvalidDummyOutput,
    #[error(transparent)]
    Tree(#[from] TreeError),
    #[error("transfer references another ring {0}")]
    ForeignRing(Address),
    #[error("a default-ring note carries ring data")]
    RingDataOutsideRing,
}

#[derive(Debug, Error)]
pub enum DepositError {
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Instruction(#[from] DepositBuildError),
    #[error(transparent)]
    Client(#[from] ClientError),
}

impl<'a> CustomRingTransfer<'a> {
    pub fn new(input: CustomRingTransferInput<'a>) -> Self {
        Self {
            ring: input.ring,
            sender: input.sender,
            prepared: input.prepared,
            interface_transfer_accounts: Vec::new(),
            tree: None,
            assets: None,
        }
    }

    #[must_use = "use the updated transfer"]
    pub fn with_tree(mut self, tree: Address) -> Self {
        self.tree = Some(tree);
        self
    }

    #[must_use = "use the updated transfer"]
    pub fn with_assets(mut self, assets: &'a AssetRegistry) -> Self {
        self.assets = Some(assets);
        self
    }

    #[must_use = "use the updated transfer"]
    pub fn with_interface_transfer_accounts(
        mut self,
        accounts: Vec<TransactInterfaceTransferAccounts>,
    ) -> Self {
        self.interface_transfer_accounts = accounts;
        self
    }

    pub fn prove<I: Rpc, R: Rpc>(
        self,
        environment: TransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenTransfer, TransferError> {
        let tree = self.tree.ok_or(TransferError::TreeRequired)?;
        let assets = self.assets.ok_or(TransferError::MissingAssetRegistry)?;
        let auditor_pk = self
            .ring
            .read_config(environment.rpc)?
            .ok_or(TransferError::MissingRingConfig)?
            .auditor_pubkey;
        // A padded change slot pushes the custom-ring instruction past the packet
        // limit even behind an address lookup table, and every published slot
        // must be one the auditor can open.
        if self.prepared.change_layout() != ChangeLayout::Compact {
            return Err(TransferError::PaddedChange);
        }
        let prepared = self.prepared;
        let program_id = self.ring.program_id();
        let allow_dummy_inputs = read_dummy_input_policy(environment.rpc, tree)?;
        RingMembership {
            program_id,
            inputs: &prepared.inputs,
            outputs: &prepared.outputs,
        }
        .validate()?;
        validate_transfer_accounts(&prepared, &self.interface_transfer_accounts)?;
        let payer = prepared.payer;
        let tx_viewing_key = self
            .sender
            .get_transaction_viewing_key(&prepared.first_nullifier)?;

        // ORDER MATTERS. The auditor message has to be inside `external_data`
        // BEFORE the SPP proof runs: SPP folds `messages` into
        // `external_data_hash` and that into `private_tx_hash`, which is element 1
        // of the custom-ring circuit's public-input chain. Proving SPP first and
        // appending the message afterwards yields two irreconcilable
        // `private_tx_hash` values -- whichever one the ring proof commits to, the
        // other is the one SPP checks. `encrypt` returning a `PendingCustomRingProof`
        // that only `finish` can turn into a witness is what makes the order
        // unforgettable: there is no `private_tx_hash` to supply yet.
        let EncryptedAudit {
            pending: pending_proof,
            message: auditor_message,
        } = CustomRingProofParams {
            tx_viewing_key: tx_viewing_key.clone(),
            auditor_pk,
        }
        .encrypt()?;
        let salt = random_salt();
        let slots = encode_confidential_slots(&prepared.outputs, assets, &tx_viewing_key, salt)?;
        let mut proof_inputs = prepared.finalize(tx_viewing_key.pubkey(), salt, slots)?;
        frame_dummy_outputs(&mut proof_inputs)?;
        proof_inputs.external_data.messages = vec![auditor_message.to_message_data(&auditor_pk)];
        // RING_TRANSACT is folded into external_data_hash and from there into
        // private_tx_hash, so it must be bound before anything hashes external data.
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;

        // Prove the SPP ring transfer over the message-bearing external data.
        let tx_shape = proof_inputs.check_shape()?;
        let ring_result = RingTransferProver {
            inputs: RingSpendInputs {
                indexer: environment.indexer,
                tree,
                spends: &proof_inputs.input_utxos,
            }
            .load()?,
            outputs: proof_inputs.output_utxos.clone(),
            external_data: proof_inputs.external_data.clone(),
            public_transfers: proof_inputs.public_transfers()?,
            signer_pk_hashes: proof_inputs.signer_pk_hashes(tx_shape.n_inputs() + 1)?,
            allow_dummy_inputs,
            ring_program_id: Some(program_id),
            shape: Some(Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs())),
        }
        .build()?;
        let spp_proof = ProofCompressed::try_from(
            environment
                .prover
                .prove_transfer_ring(&ring_result.inputs)?,
        )?
        .to_transact_proof();

        // Now the real `private_tx_hash` exists, so the pending encryption can be
        // finished into the proof request over the unchanged ciphertext. The program
        // recomputes that same public-input chain from the payload and the config
        // account.
        // One proof carries the audit and the policy statement.
        let private_tx_hash = ring_result.private_tx_hash.try_into()?;
        let policy_config = self
            .ring
            .read_policy_config(environment.rpc)?
            .ok_or(TransferError::MissingPolicyConfig)?;
        let witness = crate::witness::CustomRingWitnessInput {
            policy: &custom_ring_interface::POLICY,
            policy_config: &policy_config,
            inputs: &proof_inputs.input_utxos,
            outputs: &proof_inputs.output_utxos,
        }
        .build(environment.indexer, environment.rpc)?;
        let policy_roots = witness.roots;
        let external_data_hash = proof_inputs
            .external_data
            .hash()
            .map_err(|_| TransferError::PolicyHashing)?;
        let request = pending_proof.finish(
            private_tx_hash,
            &external_data_hash,
            witness,
            &policy_config.policy_hash,
        )?;
        let proof = to_instruction_proof(environment.prover.prove(&request)?)?;

        Ok(ProvenTransfer {
            tx_viewing_key,
            data: RingEddsaInstructionData {
                proof_inputs: &proof_inputs,
                result: &ring_result,
                proof: spp_proof,
            }
            .assemble()?,
            proof,
            owner_signers: proof_inputs.owner_signer_pubkeys()?,
            interface_transfer_accounts: self.interface_transfer_accounts,
            state_root_index: policy_roots.state_index,
            nullifier_root_index: policy_roots.nullifier_index,
            payer,
            tree,
            ring: self.ring,
        })
    }
}

impl ProvenTransfer {
    pub fn instruction(&self) -> Result<Instruction, TransferError> {
        CustomRingTransact {
            ring: self.ring,
            payer: self.payer,
            input_tree: self.tree,
            output_tree: self.tree,
            owner_signers: self.owner_signers.clone(),
            interface_transfer_accounts: self.interface_transfer_accounts.clone(),
            proof: self.proof,
            transact: self.data.clone(),
            state_root_index: self.state_root_index,
            nullifier_root_index: self.nullifier_root_index,
        }
        .instruction()
        .map_err(Into::into)
    }
}

impl RingDeposit<'_> {
    pub fn send<R: Rpc>(self, rpc: &R) -> Result<RingDepositReceipt, DepositError> {
        let blinding = random_blinding();
        let deposit = RingAssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: self.recipient.recipient_bootstrap_view_tag(),
            owner_utxo_hash: owner_utxo_hash(&self.recipient.owner_hash()?, &blinding)?,
            amount: self.amount,
            data_hash: None,
            ring_data_hash: NO_RING_DATA_HASH,
            encrypted: RingDepositPlaintext {
                blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&self.recipient.viewing_pubkey())?,
        };
        let ix = Deposit {
            ring: self.ring,
            tree: self.tree,
            depositor: self.payer.pubkey(),
            deposits: vec![deposit],
        }
        .instruction()?;
        let signature =
            rpc.create_and_send_transaction(&[ix], self.payer.pubkey(), &[self.payer])?;
        Ok(RingDepositReceipt {
            signature,
            utxo: Utxo {
                owner: self.recipient.signing_pubkey(),
                asset: SOL_MINT,
                amount: self.amount,
                blinding,
                ring_program_id: Some(self.ring.program_id()),
                data: Data::default(),
            },
        })
    }
}

fn read_dummy_input_policy<R: Rpc>(rpc: &R, tree: Address) -> Result<bool, TransferError> {
    let mut account = rpc.get_account(tree)?.ok_or(TransferError::MissingTree)?;
    if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
        return Err(TransferError::InvalidTreeOwner);
    }
    if account.data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(TransferError::InvalidTreeDiscriminator);
    }
    let mut tree_account = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())?;
    let allow_dummy_inputs = tree_account.allow_dummy_inputs()?;
    Ok(allow_dummy_inputs)
}

struct RingMembership<'a> {
    program_id: Address,
    inputs: &'a [SppProofInputUtxo],
    outputs: &'a [SppProofOutputUtxo],
}

impl RingMembership<'_> {
    fn validate(self) -> Result<(), TransferError> {
        let foreign = self
            .inputs
            .iter()
            .map(|input| input.utxo.ring_program_id)
            .chain(self.outputs.iter().map(|output| output.ring_program_id))
            .flatten()
            .find(|program_id| *program_id != self.program_id);
        if let Some(program_id) = foreign {
            return Err(TransferError::ForeignRing(program_id));
        }
        let data_outside = self
            .inputs
            .iter()
            .map(|input| (input.utxo.ring_program_id, input.ring_data_hash))
            .chain(
                self.outputs
                    .iter()
                    .map(|output| (output.ring_program_id, output.ring_data_hash)),
            )
            .any(|(ring, data)| ring.is_none() && data.is_some());
        if data_outside {
            return Err(TransferError::RingDataOutsideRing);
        }
        Ok(())
    }
}

fn validate_transfer_accounts(
    prepared: &PreparedTransfer,
    accounts: &[TransactInterfaceTransferAccounts],
) -> Result<(), TransferError> {
    let transfers = prepared
        .interface_transfers
        .iter()
        .copied()
        .map(|transfer| transfer.interface_transfer())
        .collect::<Vec<_>>();
    SettlementAccountValidation {
        transfers: &transfers,
        accounts,
    }
    .validate()?;
    Ok(())
}

/// A dummy copies the length of a real slot with its ring binding, else of the first real slot.
fn frame_dummy_outputs(proof_inputs: &mut SppProofInputs) -> Result<(), TransferError> {
    let templates: Vec<(bool, usize)> = proof_inputs
        .output_utxos
        .iter()
        .zip(&proof_inputs.external_data.outputs)
        .filter(|(output, _)| !output.is_dummy())
        .map(|(output, encoded)| {
            encoded
                .data
                .as_ref()
                .map(|data| (output.ring_program_id.is_some(), data.len()))
                .ok_or(TransferError::InvalidDummyOutput)
        })
        .collect::<Result<_, _>>()?;
    for (output, encoded) in proof_inputs
        .output_utxos
        .iter()
        .zip(&mut proof_inputs.external_data.outputs)
    {
        if !output.is_dummy() {
            continue;
        }
        let in_ring = output.ring_program_id.is_some();
        let (_, encoded_len) = templates
            .iter()
            .find(|(ring, _)| *ring == in_ring)
            .or_else(|| templates.first())
            .copied()
            .ok_or(TransferError::InvalidDummyOutput)?;
        let key = ViewingKey::new().pubkey();
        let ciphertext_len = encoded_len
            .checked_sub(1 + 4 + 1 + key.as_bytes().len())
            .filter(|len| *len > 0)
            .ok_or(TransferError::InvalidDummyOutput)?;
        let mut ciphertext = vec![0u8; ciphertext_len];
        OsRng.fill_bytes(&mut ciphertext);
        let mut body = Vec::with_capacity(1 + key.as_bytes().len() + ciphertext_len);
        body.push(if in_ring {
            EncryptedScheme::RingConfidential.as_byte()
        } else {
            EncryptedScheme::Confidential.as_byte()
        });
        body.extend_from_slice(key.as_bytes());
        body.extend_from_slice(&ciphertext);
        encoded.data = Some(borsh::to_vec(&OutputDataEncoding::Encrypted(body))?);
    }
    Ok(())
}

#[must_use = "use the updated transfer"]
struct RingSpendInputs<'a, I: Rpc> {
    indexer: &'a I,
    tree: Address,
    spends: &'a [SppProofInputUtxo],
}

impl<I: Rpc> RingSpendInputs<'_, I> {
    fn load(self) -> Result<Vec<TransferSpendInput>, TransferError> {
        let real_hashes = self
            .spends
            .iter()
            .filter(|spend| !spend.is_dummy())
            .map(SppProofInputUtxo::hash)
            .collect::<Result<Vec<_>, _>>()?;
        let nullifiers = self
            .spends
            .iter()
            .map(SppProofInputUtxo::nullifier)
            .collect::<Result<Vec<_>, _>>()?;
        let states = self
            .indexer
            .get_merkle_proofs(self.tree, real_hashes, None)?
            .proofs;
        let non_inclusions = self
            .indexer
            .get_non_inclusion_proofs(self.tree, nullifiers, None)?
            .proofs;
        let real_count = self.spends.iter().filter(|spend| !spend.is_dummy()).count();
        if states.len() != real_count || non_inclusions.len() != self.spends.len() {
            return Err(TransferError::IncompleteProofSet);
        }
        let mut states = states.into_iter();
        self.spends
            .iter()
            .zip(non_inclusions)
            .map(|(spend, nullifier)| {
                let (proof, nullifier_proof) = if spend.is_dummy() {
                    (None, Some(nullifier))
                } else {
                    let state = states.next().ok_or(TransferError::IncompleteProofSet)?;
                    (Some(SpendProof { state, nullifier }), None)
                };
                Ok(TransferSpendInput {
                    utxo: spend.utxo.clone(),
                    nullifier_key: spend.nullifier_key.clone(),
                    data_hash: None,
                    ring_data_hash: None,
                    proof,
                    nullifier_proof,
                })
            })
            .collect()
    }
}

#[must_use]
struct RingEddsaInstructionData<'a> {
    proof_inputs: &'a SppProofInputs,
    result: &'a RingTransferProofResult,
    proof: TransactProof,
}

impl RingEddsaInstructionData<'_> {
    fn assemble(self) -> Result<TransactIxData, TransferError> {
        let n_inputs = self.proof_inputs.check_shape()?.n_inputs();
        let inputs: Vec<InputUtxo> = self
            .result
            .nullifiers
            .iter()
            .zip(self.result.input_root_indices.iter())
            .map(
                |(nullifier_hash, &(utxo_tree_root_index, nullifier_tree_root_index))| InputUtxo {
                    nullifier_hash: *nullifier_hash,
                    nullifier_tree_root_index,
                    utxo_tree_root_index,
                },
            )
            .collect();
        if inputs.len() != n_inputs {
            return Err(TransferError::IncompleteInputSet);
        }

        let external = &self.proof_inputs.external_data;
        Ok(TransactIxData {
            proof: self.proof,
            expiry_unix_ts: external.expiry_unix_ts,
            private_tx_hash: self.result.private_tx_hash,
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
}

#[cfg(test)]
mod tests {
    use zolana_interface::instruction::{
        instruction_data::transact::{
            confidential_encrypted_output_body, ring_confidential_encrypted_output_body,
        },
        TransactSolTransferAccounts,
    };
    use zolana_transaction::instructions::transact::{ConfidentialTransfer, SettlementTarget};

    use super::*;

    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([42u8; 32]))
    }

    fn prepared_transfer(amount: u64) -> (ShieldedKeypair, PreparedTransfer) {
        let sender = ShieldedKeypair::new_ed25519().expect("sender");
        let recipient = ShieldedKeypair::new_ed25519().expect("recipient");
        let input = SppProofInputUtxo::new(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: Some(ring().program_id()),
                data: Data::default(),
            },
            &sender,
        );
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("sender address"),
            vec![input],
            sender.pubkey(),
        );
        transfer
            .send(
                &recipient.shielded_address().expect("recipient address"),
                SOL_MINT,
                amount,
            )
            .expect("recipient");
        (sender, transfer.prepare().expect("prepared transfer"))
    }

    #[test]
    fn membership_accepts_active_and_default_outputs() {
        let (_sender, mut prepared) = prepared_transfer(4);
        RingMembership {
            program_id: ring().program_id(),
            inputs: &prepared.inputs,
            outputs: &prepared.outputs,
        }
        .validate()
        .expect("default outputs");
        prepared.outputs[1].ring_program_id = Some(ring().program_id());
        RingMembership {
            program_id: ring().program_id(),
            inputs: &prepared.inputs,
            outputs: &prepared.outputs,
        }
        .validate()
        .expect("active ring output");
        prepared.outputs[1].ring_program_id = Some(Address::new_from_array([9u8; 32]));
        assert!(matches!(
            RingMembership {
                program_id: ring().program_id(),
                inputs: &prepared.inputs,
                outputs: &prepared.outputs,
            }
            .validate(),
            Err(TransferError::ForeignRing(_))
        ));
    }

    #[test]
    fn membership_refuses_ring_data_outside_a_ring() {
        let (_sender, mut prepared) = prepared_transfer(4);
        prepared.outputs[1].ring_data_hash = Some([3u8; 32]);
        assert!(matches!(
            RingMembership {
                program_id: ring().program_id(),
                inputs: &prepared.inputs,
                outputs: &prepared.outputs,
            }
            .validate(),
            Err(TransferError::RingDataOutsideRing)
        ));
        prepared.outputs[1].ring_program_id = Some(ring().program_id());
        RingMembership {
            program_id: ring().program_id(),
            inputs: &prepared.inputs,
            outputs: &prepared.outputs,
        }
        .validate()
        .expect("ring data inside the ring");
    }

    #[test]
    fn withdrawal_accounts_are_validated_before_proving() {
        let (sender, _) = prepared_transfer(4);
        let input = SppProofInputUtxo::new(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: Some(ring().program_id()),
                data: Data::default(),
            },
            &sender,
        );
        let recipient = Address::new_from_array([7u8; 32]);
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("sender address"),
            vec![input],
            sender.pubkey(),
        );
        transfer
            .withdraw(
                SOL_MINT,
                4,
                SettlementTarget::Sol {
                    user_sol_account: recipient,
                },
            )
            .expect("withdrawal");
        let prepared = transfer.prepare().expect("prepared withdrawal");
        assert!(matches!(
            validate_transfer_accounts(&prepared, &[]),
            Err(TransferError::Client(
                ClientError::SettlementTransferCountMismatch { .. }
            ))
        ));
        validate_transfer_accounts(
            &prepared,
            &[TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient },
            )],
        )
        .expect("withdrawal accounts");
    }

    #[test]
    fn output_framing_selects_ring_membership() {
        let (sender, mut prepared) = prepared_transfer(4);
        let tx_viewing_key = sender
            .get_transaction_viewing_key(&prepared.first_nullifier)
            .expect("transaction viewing key");
        let salt = random_salt();
        let default_slots = encode_confidential_slots(
            &prepared.outputs,
            &AssetRegistry::default(),
            &tx_viewing_key,
            salt,
        )
        .expect("default slots");
        assert!(default_slots.iter().flatten().all(|slot| {
            confidential_encrypted_output_body(&slot.data).is_some()
                && ring_confidential_encrypted_output_body(&slot.data).is_none()
        }));

        for output in &mut prepared.outputs {
            output.ring_program_id = Some(ring().program_id());
        }
        let ring_slots = encode_confidential_slots(
            &prepared.outputs,
            &AssetRegistry::default(),
            &tx_viewing_key,
            salt,
        )
        .expect("ring slots");
        assert!(ring_slots.iter().flatten().all(|slot| {
            ring_confidential_encrypted_output_body(&slot.data).is_some()
                && confidential_encrypted_output_body(&slot.data).is_none()
        }));
    }

    #[test]
    fn a_dummy_takes_the_length_of_a_real_slot_with_its_own_binding() {
        // Padded layout, the SPL change slot is a dummy, the SOL change is real.
        let (sender, mut prepared) = prepared_transfer(4);
        prepared.outputs[1].ring_program_id = Some(ring().program_id());
        let tx_viewing_key = sender
            .get_transaction_viewing_key(&prepared.first_nullifier)
            .expect("transaction viewing key");
        let salt = random_salt();
        let slots = encode_confidential_slots(
            &prepared.outputs,
            &AssetRegistry::default(),
            &tx_viewing_key,
            salt,
        )
        .expect("slots");
        let mut proof_inputs = prepared
            .finalize(tx_viewing_key.pubkey(), salt, slots)
            .expect("proof inputs");
        let real_len = |in_ring: bool| {
            proof_inputs
                .output_utxos
                .iter()
                .zip(&proof_inputs.external_data.outputs)
                .find(|(output, _)| {
                    !output.is_dummy() && output.ring_program_id.is_some() == in_ring
                })
                .and_then(|(_, output)| output.data.as_ref().map(Vec::len))
                .expect("real output data")
        };
        let (ring_len, default_len) = (real_len(true), real_len(false));
        assert_ne!(ring_len, default_len);
        frame_dummy_outputs(&mut proof_inputs).expect("mixed framing");
        assert!(proof_inputs
            .output_utxos
            .iter()
            .any(|output| output.is_dummy()));
        for (output, encoded) in proof_inputs
            .output_utxos
            .iter()
            .zip(&proof_inputs.external_data.outputs)
            .filter(|(output, _)| output.is_dummy())
        {
            let data = encoded.data.as_deref().expect("dummy output data");
            assert_eq!(data.len(), default_len);
            assert!(output.ring_program_id.is_none());
            assert!(ring_confidential_encrypted_output_body(data).is_none());
        }
    }

    #[test]
    fn dummy_framing_matches_ring_slot_lengths() {
        let (sender, mut prepared) = prepared_transfer(10);
        for output in &mut prepared.outputs {
            output.ring_program_id = Some(ring().program_id());
        }
        let tx_viewing_key = sender
            .get_transaction_viewing_key(&prepared.first_nullifier)
            .expect("transaction viewing key");
        let salt = random_salt();
        let slots = encode_confidential_slots(
            &prepared.outputs,
            &AssetRegistry::default(),
            &tx_viewing_key,
            salt,
        )
        .expect("slots");
        let mut proof_inputs = prepared
            .finalize(tx_viewing_key.pubkey(), salt, slots)
            .expect("proof inputs");
        assert!(
            proof_inputs
                .output_utxos
                .iter()
                .filter(|output| output.is_dummy())
                .count()
                >= 2
        );
        let real_len = proof_inputs
            .output_utxos
            .iter()
            .zip(&proof_inputs.external_data.outputs)
            .find(|(output, _)| !output.is_dummy())
            .and_then(|(_, output)| output.data.as_ref().map(Vec::len))
            .expect("real output data");
        frame_dummy_outputs(&mut proof_inputs).expect("dummy framing");
        let lengths = proof_inputs
            .external_data
            .outputs
            .iter()
            .map(|output| output.data.as_ref().expect("output data").len())
            .collect::<Vec<_>>();
        assert!(proof_inputs.external_data.outputs.iter().all(|output| {
            output
                .data
                .as_deref()
                .and_then(ring_confidential_encrypted_output_body)
                .is_some()
        }));
        assert!(lengths.iter().all(|length| *length == real_len));
        let dummy_keys = proof_inputs
            .output_utxos
            .iter()
            .zip(&proof_inputs.external_data.outputs)
            .filter(|(output, _)| output.is_dummy())
            .map(|(_, output)| {
                let body = ring_confidential_encrypted_output_body(
                    output.data.as_deref().expect("dummy output data"),
                )
                .expect("dummy confidential body");
                body[..33].to_vec()
            })
            .collect::<Vec<_>>();
        assert_ne!(dummy_keys[0], dummy_keys[1]);
    }
}
