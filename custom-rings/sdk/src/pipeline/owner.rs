use rand::{rngs::OsRng, RngCore};
use solana_address::Address;
use zolana_client::{AsyncRpc, ProofInputUtxo, SettlementAccountValidation};
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::{tag::RING_TRANSACT, OwnerTag, TransactOutput},
    MAX_INPUT_TREES,
};
use zolana_keypair::{NullifierKey, ShieldedAddress, ViewingKey};
use zolana_program::instruction::TransactInterfaceTransferAccounts;
use zolana_ring_policy::{ListNamespace, Member, VelocityMode};
use zolana_transaction::{
    instructions::transact::{
        ConfidentialTransaction, ResolvedOwnerTag, SppProofInputs, SppProofOutputUtxo,
    },
    serialization::confidential::ConfidentialOutputPlaintext,
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    Data, EncryptedScheme, Mint, ShieldedKeys, TransactionError,
};

use super::{
    sealed, CompressedDisclosure, Rail, RailKind, RingTransfer, Staged, TransferAuthority,
};
use crate::{
    escrow::KeyRegistry,
    velocity::{charge, transaction_key, Outflows, RecordSpend, VelocityContext, VelocityPlan},
    CustomRing, CustomRingConfig, CustomRingProofParams, EncryptedAudit, ReadSpendRecord,
    RingError, RingIdentity, VelocityProofInput,
};

/// The sender's spends, it signs the assembled Solana transaction itself.
pub struct Owner<'a> {
    sender: &'a (dyn ShieldedKeys + Send + Sync),
    nullifier_key: Option<&'a NullifierKey>,
    transaction: ConfidentialTransaction,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
}

pub struct CustomRingTransferInput<'a> {
    pub ring: CustomRing,
    /// Only transaction keys and the address are read, the signing key may live elsewhere.
    pub sender: &'a (dyn ShieldedKeys + Send + Sync),
    /// Completes the real inputs, `None` only for an all-padding transfer.
    pub nullifier_key: Option<&'a NullifierKey>,
    /// The transaction with its output slots already padded to its shape.
    pub transaction: ConfidentialTransaction,
}

impl sealed::Sealed for Owner<'_> {}

impl Rail for Owner<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Owner(self)
    }
}

impl<'a> RingTransfer<Owner<'a>> {
    pub fn new(input: CustomRingTransferInput<'a>) -> Self {
        Self {
            ring: input.ring,
            rail: Owner {
                sender: input.sender,
                nullifier_key: input.nullifier_key,
                transaction: input.transaction,
                interface_transfer_accounts: Vec::new(),
            },
            cosigner: None,
            indexer_config: None,
        }
    }

    #[must_use = "use the updated transfer"]
    pub fn with_interface_transfer_accounts(
        mut self,
        accounts: Vec<TransactInterfaceTransferAccounts>,
    ) -> Self {
        self.rail.interface_transfer_accounts = accounts;
        self
    }
}

/// The window read is the one transport-bound step of a limit.
enum Limit {
    Unbounded,
    PerTransfer(RingIdentity, Vec<zolana_ring_policy::VelocityRow>),
    PerWindow(Box<crate::velocity::VelocityFacts>),
}

impl Owner<'_> {
    /// Record openings and the auditor ciphertext precede every hash over the external data.
    pub(super) async fn stage(
        &self,
        ring: CustomRing,
        client: &(impl AsyncRpc + ?Sized),
        config: &CustomRingConfig,
    ) -> Result<Staged, RingError> {
        let sender = self.sender.address()?;
        let member = Member::from_bytes(sender.signing_pubkey.owner_proof_input_hash()?)?;
        let pinned = match config.has_policy {
            true => Some(
                ring.pinned_policy(client)
                    .await?
                    .ok_or(RingError::MissingPolicyConfig)?,
            ),
            false => None,
        };
        let limit = match &pinned {
            None => Limit::Unbounded,
            Some(pinned) => {
                let identity = RingIdentity::new(ring, pinned.config.namespace_owner_hash)?;
                let rows = pinned.table.velocity().to_vec();
                match pinned.table.velocity_mode() {
                    VelocityMode::Off => Limit::Unbounded,
                    VelocityMode::PerTransfer => Limit::PerTransfer(identity, rows),
                    VelocityMode::PerWindow { window_slots } => {
                        let tree_id = pinned.config.address_tree_id();
                        let live = ReadSpendRecord::new(ring, tree_id, member)
                            .current(client)
                            .await?
                            .ok_or(RingError::SpendRecordMissing)?;
                        let context = VelocityContext {
                            namespace: ring.namespace_pda(),
                            owner: ListNamespace {
                                owner_hash: pinned.config.namespace_owner_hash,
                            },
                            identity,
                            address_tree_id: tree_id,
                            window_slots,
                            rows,
                        };
                        let slot = client.get_slot().await?;
                        Limit::PerWindow(Box::new(context.facts(self.sender, live, slot)?))
                    }
                }
            }
        };
        let transaction = &self.transaction;
        if let Limit::PerWindow(facts) = &limit {
            check_record_tree_count(transaction, facts.live.tree_id)?;
        }
        let program = ring.program_id();
        let transfers: Vec<_> = transaction
            .interface_transfers()?
            .into_iter()
            .map(|transfer| transfer.interface_transfer())
            .collect();
        SettlementAccountValidation {
            transfers: &transfers,
            accounts: &self.interface_transfer_accounts,
        }
        .validate()?;
        let tx_viewing_key = transaction_key(self.sender, *transaction.first_nullifier())?;
        let sender_tag = transaction.sender_owner_tag(&sender.signing_pubkey)?;
        let mut proof_inputs = transaction
            .clone()
            .encrypt_with_viewing_key(&sender, &tx_viewing_key)?;
        check_membership(
            program,
            &proof_inputs.input_utxos,
            &proof_inputs.output_utxos,
        )?;
        proof_inputs.check_shape()?;
        let first_nullifier = proof_inputs.first_nullifier()?;
        let output_blinding_seed =
            derive_output_blinding_seed(&first_nullifier, &proof_inputs.blinding_seed)?;
        let salt = proof_inputs.external_data.salt;
        let outflows = || Outflows {
            sender: member,
            ring: program,
            inputs: &proof_inputs.input_utxos,
            outputs: &proof_inputs.output_utxos,
        };
        let (velocity, plan) = match &limit {
            Limit::Unbounded => (None, None),
            Limit::PerTransfer(identity, rows) => {
                let charges = charge(rows, &outflows(), None)?;
                (
                    Some(VelocityProofInput::per_transfer(&charges, *identity)),
                    None,
                )
            }
            Limit::PerWindow(facts) => {
                let plan = facts.plan(RecordSpend {
                    outflows: outflows(),
                    tx_viewing_key: &tx_viewing_key,
                    salt,
                    first_nullifier,
                    output_blinding_seed,
                    money_shape: money_shape(&proof_inputs),
                })?;
                (Some(plan.proof_input), Some(plan))
            }
        };
        let mut messages = Vec::with_capacity(3);
        let mut record = None;
        if let Some(plan) = plan {
            append_record(
                &mut proof_inputs,
                &plan,
                &tx_viewing_key,
                &sender,
                sender_tag,
            )?;
            let body = plan
                .counters_message
                .data
                .as_slice()
                .try_into()
                .map_err(|_| RingError::SpendCountersUnknown)?;
            record = Some(CompressedDisclosure {
                transaction_salt: salt,
                counters_disclosure_hash: zolana_ring_policy::spend_counters_disclosure_hash(
                    &salt, body,
                )?,
            });
            messages.extend([plan.record_message, plan.counters_message]);
        }
        frame_dummy_outputs(
            &proof_inputs.output_utxos,
            &mut proof_inputs.external_data.outputs,
        )?;
        let EncryptedAudit { pending, message } = CustomRingProofParams {
            tx_viewing_key: tx_viewing_key.clone(),
            auditor_pk: config.auditor_pubkey,
            salt,
            outputs: proof_inputs
                .output_utxos
                .iter()
                .filter(|output| !output.is_compact())
                .map(|output| ProofInputUtxo::try_from((output, proof_inputs.output_tree_id)))
                .collect::<Result<_, _>>()?,
        }
        .encrypt()?;
        messages.push(message.to_message_data(&config.auditor_pubkey));
        proof_inputs.external_data.messages = messages;
        // The external data hash binds the instruction tag.
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;
        let spend_record = record
            .map(|_| {
                record_input_position(&proof_inputs.input_utxos).ok_or(TransactionError::NoInputs)
            })
            .transpose()?;
        Ok(Staged {
            owner_signers: proof_inputs.owner_signer_pubkeys()?,
            proof_inputs,
            pending,
            tx_viewing_key,
            pinned,
            velocity,
            record,
            authority: TransferAuthority {
                owner: self.nullifier_key.cloned(),
                spend_record,
            },
            key_registry: KeyRegistry::of(ring, config),
            interface_transfer_accounts: self.interface_transfer_accounts.clone(),
            delegate: None,
        })
    }
}

pub(super) fn check_record_tree_count(
    transaction: &ConfidentialTransaction,
    record_tree: u16,
) -> Result<(), RingError> {
    let trees = transaction.input_tree_ids();
    let got = trees.len() + usize::from(!trees.contains(&record_tree));
    if got > MAX_INPUT_TREES {
        return Err(TransactionError::TooManyInputTrees {
            got,
            max: MAX_INPUT_TREES,
        }
        .into());
    }
    Ok(())
}

/// Every ring field names this ring, and only a ring note carries ring data.
pub(crate) fn check_membership(
    program: Address,
    inputs: &[SppProofInputUtxo],
    outputs: &[SppProofOutputUtxo],
) -> Result<(), RingError> {
    let slots = inputs
        .iter()
        .map(|input| (input.utxo.ring_program_id, input.ring_data_hash))
        .chain(
            outputs
                .iter()
                .map(|output| (output.ring_program_id, output.ring_data_hash)),
        );
    for (ring, data) in slots {
        match ring {
            Some(ring) if ring != program => return Err(RingError::ForeignRing(ring)),
            None if data.is_some() => return Err(RingError::RingDataOutsideRing),
            _ => {}
        }
    }
    Ok(())
}

/// The real money slots, non-dummy inputs and the outputs ahead of the first dummy.
pub(crate) fn money_shape(proof_inputs: &SppProofInputs) -> zolana_client::Shape {
    zolana_client::Shape::new(
        proof_inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_dummy())
            .count(),
        proof_inputs
            .output_utxos
            .iter()
            .take_while(|output| !output.is_dummy())
            .count(),
    )
}

pub(crate) fn record_input_position(inputs: &[SppProofInputUtxo]) -> Option<usize> {
    inputs.iter().rposition(|input| !input.is_dummy())
}

/// The record follows the real inputs, padding sits under the last declared tree as SPP pads.
pub(crate) fn place_record_input(
    inputs: &mut Vec<SppProofInputUtxo>,
    record: SppProofInputUtxo,
    n_inputs: usize,
) -> Result<(), RingError> {
    inputs.retain(|input| !input.is_dummy());
    inputs.push(record);
    let mut padding_tree = inputs[0].tree_id;
    for (index, input) in inputs.iter().enumerate() {
        if inputs[..index]
            .iter()
            .all(|earlier| earlier.tree_id != input.tree_id)
        {
            padding_tree = input.tree_id;
        }
    }
    while inputs.len() < n_inputs {
        inputs.push(SppProofInputUtxo::dummy(padding_tree)?);
    }
    Ok(())
}

/// The record takes the slot after the money, its successor blinding derives from that index.
pub(crate) fn append_record(
    proof_inputs: &mut SppProofInputs,
    plan: &VelocityPlan,
    tx_viewing_key: &ViewingKey,
    sender: &ShieldedAddress,
    sender_tag: ResolvedOwnerTag,
) -> Result<(), RingError> {
    let money = money_shape(proof_inputs);
    if money.n_inputs() + 1 > plan.shape.n_inputs()
        || money.n_outputs() + 1 > plan.shape.n_outputs()
    {
        return Err(RingError::PolicyShapeUnsupported);
    }
    place_record_input(
        &mut proof_inputs.input_utxos,
        plan.input.clone(),
        plan.shape.n_inputs(),
    )?;
    let money = money.n_outputs();
    proof_inputs.output_utxos.truncate(money);
    proof_inputs.external_data.outputs.truncate(money);
    proof_inputs
        .external_data
        .resolved_owner_tags
        .truncate(money);
    let first_nullifier = proof_inputs.first_nullifier()?;
    let seed = derive_output_blinding_seed(&first_nullifier, &proof_inputs.blinding_seed)?;
    let blinding = |slot: usize| -> Result<[u8; 32], RingError> {
        let slot = u32::try_from(slot).map_err(|_| RingError::PolicyShapeUnsupported)?;
        Ok(derive_transact_output_blinding(
            &first_nullifier,
            &seed,
            slot,
        )?)
    };
    let (owner, asset, padding_tag) = padding_template(proof_inputs, sender, sender_tag);
    while proof_inputs.output_utxos.len() < plan.record_slot {
        let output = SppProofOutputUtxo {
            blinding: blinding(proof_inputs.output_utxos.len())?,
            ..SppProofOutputUtxo::new(asset, 0, owner)?
        };
        push_output(proof_inputs, output, tx_viewing_key, Some(padding_tag))?;
    }
    let slot = proof_inputs.output_utxos.len();
    if plan.output.blinding != blinding(slot)? {
        return Err(zolana_client::ClientError::OutputBlindingMismatch { index: slot }.into());
    }
    push_output(proof_inputs, plan.output.clone(), tx_viewing_key, None)?;
    while proof_inputs.output_utxos.len() < plan.shape.n_outputs() {
        proof_inputs.output_utxos.push(SppProofOutputUtxo {
            blinding: blinding(proof_inputs.output_utxos.len())?,
            compact: true,
            ..Default::default()
        });
    }
    Ok(())
}

/// `None` tags the slot inline with its owner's view tag.
fn push_output(
    proof_inputs: &mut SppProofInputs,
    output: SppProofOutputUtxo,
    tx_viewing_key: &ViewingKey,
    tag: Option<ResolvedOwnerTag>,
) -> Result<(), RingError> {
    let slot = proof_inputs.output_utxos.len() as u32;
    let sealed = output.seal(slot, tx_viewing_key, proof_inputs.external_data.salt)?;
    let tag = tag.unwrap_or(ResolvedOwnerTag {
        tag: OwnerTag::Inline(sealed.view_tag),
        resolved: sealed.view_tag,
    });
    proof_inputs.external_data.outputs.push(TransactOutput {
        utxo_hash: output.hash(proof_inputs.output_tree_id)?,
        owner_tag: tag.tag,
        data: Some(sealed.data),
    });
    proof_inputs
        .external_data
        .resolved_owner_tags
        .push(tag.resolved);
    proof_inputs.output_utxos.push(output);
    Ok(())
}

/// Padding copies the sender's change, else the last money output, else the sender's zero SOL.
fn padding_template(
    proof_inputs: &SppProofInputs,
    sender: &ShieldedAddress,
    sender_tag: ResolvedOwnerTag,
) -> (ShieldedAddress, Mint, ResolvedOwnerTag) {
    let external = &proof_inputs.external_data;
    let mut money = proof_inputs
        .output_utxos
        .iter()
        .zip(&external.outputs)
        .zip(&external.resolved_owner_tags)
        .filter_map(|((output, encoded), resolved)| {
            output.owner_address.map(|address| {
                let tag = ResolvedOwnerTag {
                    tag: encoded.owner_tag,
                    resolved: *resolved,
                };
                (address, output.asset, tag)
            })
        });
    money
        .clone()
        .find(|(address, ..)| address.signing_pubkey == sender.signing_pubkey)
        .or_else(|| money.next_back())
        .unwrap_or((*sender, Mint::SOL, sender_tag))
}

/// A dummy copies the length of a real slot with its ring binding, else of the first real slot.
pub(crate) fn frame_dummy_outputs(
    outputs: &[SppProofOutputUtxo],
    encoded: &mut [TransactOutput],
) -> Result<(), RingError> {
    let templates: Vec<(bool, usize)> = outputs
        .iter()
        .zip(encoded.iter())
        .filter(|(output, _)| !output.is_dummy())
        .map(|(output, encoded)| {
            let len = encoded
                .data
                .as_ref()
                .ok_or(RingError::InvalidDummyOutput)?
                .len();
            Ok((output.ring_program_id.is_some(), len))
        })
        .collect::<Result<_, RingError>>()?;
    for (output, encoded) in outputs.iter().zip(encoded.iter_mut()) {
        if !output.is_dummy() {
            continue;
        }
        let in_ring = output.ring_program_id.is_some();
        let key = ViewingKey::new().pubkey();
        let template = templates
            .iter()
            .find(|(ring, _)| *ring == in_ring)
            .or_else(|| templates.first());
        let ciphertext_len = match template {
            Some((_, len)) => len
                .checked_sub(1 + 4 + 1 + key.as_bytes().len())
                .filter(|len| *len > 0)
                .ok_or(RingError::InvalidDummyOutput)?,
            None => ConfidentialOutputPlaintext {
                asset_id: zolana_transaction::SOL_ASSET_ID,
                amount: 0,
                blinding: [0; 32],
                ring_program_id: output.ring_program_id,
                data: Data::default(),
            }
            .serialize()?
            .len(),
        };
        let scheme = match in_ring {
            true => EncryptedScheme::RingConfidential,
            false => EncryptedScheme::Confidential,
        };
        let mut body = vec![scheme.as_byte()];
        body.extend_from_slice(key.as_bytes());
        let start = body.len();
        body.resize(start + ciphertext_len, 0);
        OsRng.fill_bytes(&mut body[start..]);
        encoded.data = Some(borsh::to_vec(&OutputDataEncoding::Encrypted(body))?);
    }
    Ok(())
}
