use custom_ring_interface::RingMode;
use rand::{rngs::OsRng, RngCore};
use solana_address::Address;
use zolana_client::{AsyncRpc, ProofInputUtxo, SettlementAccountValidation};
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::{tag::RING_TRANSACT, TransactOutput},
};
use zolana_keypair::{NullifierKey, ViewingKey};
use zolana_program::instruction::TransactInterfaceTransferAccounts;
use zolana_ring_policy::{Member, OutflowLimit};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, SppProofOutputUtxo},
    keys::TransactionKeyRequest,
    serialization::confidential::ConfidentialOutputPlaintext,
    utxo::SppProofInputUtxo,
    Data, EncryptedScheme, ShieldedKeys, TransactionError,
};

use super::{
    anonymous::{anonymous_disclosure, check_anonymous_slots},
    pinned_policy, sealed, Rail, RailKind, RingTransfer, Staged, TransferAuthority,
};
use crate::{
    heap::boxed,
    limits::{bound, Outflows},
    CustomRing, CustomRingConfig, CustomRingProofParams, EncryptedAudit, RingError, RingIdentity,
};

/// The sender's spends, it signs the assembled Solana transaction itself.
pub struct Owner<'a> {
    pub(super) sender: &'a (dyn ShieldedKeys + Send + Sync),
    nullifier_key: Option<&'a NullifierKey>,
    pub(super) transaction: ConfidentialTransaction,
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

/// The pinned limits a member transfer is bounded by.
enum Limit {
    Unbounded,
    Bounded(RingIdentity, Vec<OutflowLimit>),
}

/// The transaction viewing key the sender derives for `first_nullifier`.
pub(crate) fn transaction_key(
    sender: &(dyn ShieldedKeys + Send + Sync),
    first_nullifier: [u8; 32],
) -> Result<ViewingKey, RingError> {
    let keys = sender.transaction_keys(&[TransactionKeyRequest {
        viewing_pubkey: sender.address()?.viewing_pubkey,
        first_nullifier,
    }])?;
    let got = keys.len();
    Ok(keys
        .into_iter()
        .next()
        .ok_or(TransactionError::IncompleteDerivation { got, want: 1 })?)
}

impl Owner<'_> {
    /// An anonymous ring admits only the hidden owner's proof.
    pub(super) async fn stage(
        &self,
        ring: CustomRing,
        client: &(impl AsyncRpc + ?Sized),
        config: &CustomRingConfig,
    ) -> Result<Box<Staged>, RingError> {
        if config.mode == RingMode::Anonymous {
            return Err(RingError::MissingAnonymousSigner);
        }
        self.stage_with(ring, client, config, false).await
    }

    /// The auditor ciphertext precedes every hash over the external data.
    pub(super) async fn stage_with(
        &self,
        ring: CustomRing,
        client: &(impl AsyncRpc + ?Sized),
        config: &CustomRingConfig,
        anonymous: bool,
    ) -> Result<Box<Staged>, RingError> {
        let sender = self.sender.address()?;
        let member = Member::from_bytes(sender.signing_pubkey.owner_proof_input_hash()?)?;
        let pinned = match config.has_policy {
            true => Some(boxed(|| pinned_policy(ring, client)).await?),
            false => None,
        };
        let limit = match &pinned {
            Some(pinned) if !pinned.table.limits().is_empty() => Limit::Bounded(
                RingIdentity::new(ring, pinned.config.namespace_owner_hash)?,
                pinned.table.limits().to_vec(),
            ),
            _ => Limit::Unbounded,
        };
        let transaction = &self.transaction;
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
        let mut proof_inputs = match anonymous {
            true => transaction
                .clone()
                .encrypt_anonymous_with_viewing_key(&sender, &tx_viewing_key)?,
            false => transaction
                .clone()
                .encrypt_with_viewing_key(&sender, &tx_viewing_key)?,
        };
        check_membership(
            program,
            &proof_inputs.input_utxos,
            &proof_inputs.output_utxos,
        )?;
        let shape = proof_inputs.check_shape()?;
        if anonymous {
            check_anonymous_slots(program, shape, &proof_inputs)?;
        }
        proof_inputs
            .external_data
            .validate_ring_output_markers(&proof_inputs.output_utxos)?;
        let limits = match &limit {
            Limit::Unbounded => None,
            Limit::Bounded(identity, limits) => {
                let outflows = Outflows {
                    sender: member,
                    ring: program,
                    inputs: &proof_inputs.input_utxos,
                    outputs: &proof_inputs.output_utxos,
                };
                Some(bound(limits, &outflows, *identity)?)
            }
        };
        frame_dummies(
            &proof_inputs.output_utxos,
            &mut proof_inputs.external_data.outputs,
            anonymous,
        )?;
        if anonymous {
            // The proof binds every hidden recipient, no published slot names an owner.
            for output in &mut proof_inputs.output_utxos {
                output.owner_tag = Some([0; 32]);
            }
        }
        let salt = proof_inputs.external_data.salt;
        let params = CustomRingProofParams {
            tx_viewing_key: tx_viewing_key.clone(),
            auditor_pk: config.auditor_pubkey,
            salt,
            outputs: proof_inputs
                .output_utxos
                .iter()
                .filter(|output| !output.is_compact())
                .map(|output| ProofInputUtxo::try_from((output, proof_inputs.output_tree_id)))
                .collect::<Result<_, _>>()?,
        };
        let EncryptedAudit { pending, message } = match anonymous {
            true => params.encrypt_anonymous(anonymous_disclosure(&sender, &proof_inputs)?)?,
            false => params.encrypt()?,
        };
        proof_inputs.external_data.messages = vec![message.to_message_data(&config.auditor_pubkey)];
        // The external data hash binds the instruction tag.
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;
        Ok(Box::new(Staged {
            owner_signers: match anonymous {
                true => Vec::new(),
                false => proof_inputs.owner_signer_pubkeys()?,
            },
            proof_inputs,
            pending,
            tx_viewing_key,
            pinned,
            limits,
            authority: TransferAuthority {
                owner: self.nullifier_key.cloned(),
            },
            key_escrow: config.mode == RingMode::Registry,
            interface_transfer_accounts: self.interface_transfer_accounts.clone(),
            delegate: None,
        }))
    }
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

/// A dummy copies the length of a real slot with its ring binding, else of the first real slot.
pub(crate) fn frame_dummy_outputs(
    outputs: &[SppProofOutputUtxo],
    encoded: &mut [TransactOutput],
) -> Result<(), RingError> {
    frame_dummies(outputs, encoded, false)
}

/// An anonymous dummy carries no recipient key, like every anonymous slot.
pub(super) fn frame_dummies(
    outputs: &[SppProofOutputUtxo],
    encoded: &mut [TransactOutput],
    anonymous: bool,
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
        let key = match anonymous {
            true => &[][..],
            false => key.as_bytes(),
        };
        let template = templates
            .iter()
            .find(|(ring, _)| *ring == in_ring)
            .or_else(|| templates.first());
        let ciphertext_len = match template {
            Some((_, len)) => len
                .checked_sub(1 + 4 + 1 + key.len())
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
        let scheme = match (anonymous, in_ring) {
            (true, _) => EncryptedScheme::RingAnonymous,
            (false, true) => EncryptedScheme::RingConfidential,
            (false, false) => EncryptedScheme::Confidential,
        };
        let mut body = vec![scheme.as_byte()];
        body.extend_from_slice(key);
        let start = body.len();
        body.resize(start + ciphertext_len, 0);
        OsRng.fill_bytes(&mut body[start..]);
        encoded.data = Some(borsh::to_vec(&OutputDataEncoding::Encrypted(body))?);
    }
    Ok(())
}
