use rand::{rngs::OsRng, RngCore};
use solana_address::Address;
use zolana_event::MessageData;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::{SALT_LEN, VIEW_TAG_LEN},
    random_salt,
    shielded::ShieldedAddress,
    viewing_key::random_blinding,
    Curve, P256Pubkey, PublicKey, ViewingKey, ViewingKeyTrait,
};

use super::{
    shape::{resolve_shape, Shape},
    slots::encode_confidential_slots,
    spp_proof_inputs::{
        assign_output_blindings, first_nullifier, inputs_require_p256, SppProofInputs,
    },
    ExternalData, SettlementTransfer, SppProofOutputUtxo,
};
use crate::{
    data::Data,
    error::TransactionError,
    instructions::types::SppProofInputUtxo,
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    utxo::derive_transact_output_blinding,
    AssetRegistry, SOL_ASSET_ID, SOL_MINT,
};

/// Fixed number of leading sender-owned output slots in a transfer: SPL change at
/// slot 0, SOL change at slot 1. Recipients always start at slot 2.
pub const SENDER_SLOT_COUNT: usize = 2;

pub struct PreparedTransfer {
    pub owner: ShieldedAddress,
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub output_blinding_seed: [u8; 32],
    pub first_nullifier: [u8; 32],
    pub shape: Shape,
    pub payer: Address,
    pub interface_transfers: Vec<SettlementTransfer>,
    output_layout: PreparedOutputLayout,
    change_layout: ChangeLayout,
}

pub struct Recipient {
    pub address: ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
    pub ring: RecipientRing,
}

/// Resolved when the transfer is prepared, so `send` and the ring binding may
/// come in any order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipientRing {
    OfTransfer,
    /// An exit when the transfer runs in a ring.
    Default,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementTarget {
    Sol {
        user_sol_account: Address,
    },
    Spl {
        user_spl_token: Address,
        spl_token_interface: Address,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicTransferRequest {
    pub asset: Address,
    pub is_deposit: bool,
    pub amount: u64,
    pub target: SettlementTarget,
}

pub struct ConfidentialTransfer {
    pub owner: ShieldedAddress,
    pub inputs: Vec<SppProofInputUtxo>,
    pub recipients: Vec<Recipient>,
    pub public_transfers: Vec<PublicTransferRequest>,
    pub payer: Address,
    pub blinding_seed: [u8; 32],
    pub shape: Option<Shape>,
    change_layout: ChangeLayout,
    /// Binds the change and every later `send` to one ring.
    ring_program_id: Option<Address>,
}

/// Whether [`ConfidentialTransfer::prepare`] keeps a change slot that holds no
/// value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeLayout {
    /// Every transfer carries both change slots, dummy or not.
    Padded,
    /// Only change slots holding value are emitted, and the shape shrinks with
    /// them.
    Compact,
}

#[derive(Clone, Copy)]
enum PreparedOutputLayout {
    BothChanges,
    SplChange,
    SolChange,
    Recipients,
}

impl ConfidentialTransfer {
    pub fn new(owner: ShieldedAddress, inputs: Vec<SppProofInputUtxo>, payer: Address) -> Self {
        Self {
            owner,
            inputs,
            recipients: Vec::new(),
            public_transfers: Vec::new(),
            payer,
            blinding_seed: random_blinding(),
            shape: None,
            change_layout: ChangeLayout::Padded,
            ring_program_id: None,
        }
    }

    /// Binds the change and every `send` to one ring.
    #[must_use]
    pub fn with_ring_program_id(mut self, ring_program_id: Address) -> Self {
        self.ring_program_id = Some(ring_program_id);
        self
    }

    /// An explicit shape passed to [`Self::with_shape`] is resolved against the
    /// compact output count.
    #[must_use]
    pub fn with_compact_change(mut self) -> Self {
        self.change_layout = ChangeLayout::Compact;
        self
    }

    pub fn with_shape(mut self, shape: Shape) -> Self {
        self.shape = Some(shape);
        self
    }

    pub fn requires_p256_owner(&self) -> Result<bool, TransactionError> {
        inputs_require_p256(&self.inputs)
    }

    /// The note joins the ring of the transfer, the default ring without one.
    pub fn send(
        &mut self,
        recipient: &ShieldedAddress,
        asset: Address,
        amount: u64,
    ) -> Result<&mut Self, TransactionError> {
        self.push(Recipient {
            address: *recipient,
            asset,
            amount,
            ring: RecipientRing::OfTransfer,
        })
    }

    /// The note leaves the ring of the transfer for the default ring.
    pub fn send_default_ring(
        &mut self,
        recipient: &ShieldedAddress,
        asset: Address,
        amount: u64,
    ) -> Result<&mut Self, TransactionError> {
        self.push(Recipient {
            address: *recipient,
            asset,
            amount,
            ring: RecipientRing::Default,
        })
    }

    fn push(&mut self, recipient: Recipient) -> Result<&mut Self, TransactionError> {
        if recipient.address.signing_pubkey.curve()? == Curve::P256 {
            return Err(TransactionError::P256TransactUnsupported);
        }
        self.recipients.push(recipient);
        Ok(self)
    }

    pub fn withdraw(
        &mut self,
        asset: Address,
        amount: u64,
        target: SettlementTarget,
    ) -> Result<&mut Self, TransactionError> {
        self.settle(asset, false, amount, target)
    }

    pub fn deposit(
        &mut self,
        asset: Address,
        amount: u64,
        target: SettlementTarget,
    ) -> Result<&mut Self, TransactionError> {
        self.settle(asset, true, amount, target)
    }

    pub fn settle(
        &mut self,
        asset: Address,
        is_deposit: bool,
        amount: u64,
        target: SettlementTarget,
    ) -> Result<&mut Self, TransactionError> {
        if amount == 0 {
            return Err(TransactionError::ZeroInterfaceTransferAmount);
        }
        validate_settlement_target(asset, target)?;
        let next_len = self.public_transfers.len().checked_add(1).ok_or(
            TransactionError::TooManyInterfaceTransfers {
                got: usize::MAX,
                max: zolana_interface::MAX_INTERFACE_TRANSFERS,
            },
        )?;
        if next_len > zolana_interface::MAX_INTERFACE_TRANSFERS {
            return Err(TransactionError::TooManyInterfaceTransfers {
                got: next_len,
                max: zolana_interface::MAX_INTERFACE_TRANSFERS,
            });
        }
        self.public_transfers.push(PublicTransferRequest {
            asset,
            is_deposit,
            amount,
            target,
        });
        Ok(self)
    }

    /// Keypair rail: assemble with the owner's own viewing key and sign in place,
    /// no separate authority. The authority rail is [`Self::prepare`] +
    /// [`PreparedTransfer::finalize`], with encryption/signing delegated to a
    /// `WalletAuthority`.
    pub fn sign<K: ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SppProofInputs, TransactionError> {
        self.assemble(keypair, assets, false)
    }

    /// Assemble a custom-ring P256 transfer. Unlike the default transact rail,
    /// the sender's P256 owner tag is carried inline because ownership is proven
    /// inside the RingP256 circuit rather than by a Solana signer account.
    pub fn sign_ring_p256<K: ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SppProofInputs, TransactionError> {
        self.assemble(keypair, assets, true)
    }

    fn assemble<K: ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
        allow_p256_sender: bool,
    ) -> Result<SppProofInputs, TransactionError> {
        let prepared = self.prepare()?;
        let transaction_viewing_key =
            keypair.get_transaction_viewing_key(&prepared.first_nullifier)?;
        let salt = random_salt();
        let tx_viewing_pk = transaction_viewing_key.pubkey();
        let slots =
            encode_confidential_slots(&prepared.outputs, assets, &transaction_viewing_key, salt)?;
        prepared.finalize_inner(tx_viewing_pk, salt, slots, allow_p256_sender)
    }

    pub fn prepare(self) -> Result<PreparedTransfer, TransactionError> {
        if self.public_transfers.len() > zolana_interface::MAX_INTERFACE_TRANSFERS {
            return Err(TransactionError::TooManyInterfaceTransfers {
                got: self.public_transfers.len(),
                max: zolana_interface::MAX_INTERFACE_TRANSFERS,
            });
        }
        if self
            .public_transfers
            .iter()
            .any(|transfer| transfer.amount == 0)
        {
            return Err(TransactionError::ZeroInterfaceTransferAmount);
        }
        for transfer in &self.public_transfers {
            validate_settlement_target(transfer.asset, transfer.target)?;
        }
        let spl_asset = self.spl_asset()?;
        let public_sol = self.public_amount(&SOL_MINT)?;
        let public_spl = match spl_asset {
            Some(asset) => self.public_amount(&asset)?,
            None => 0,
        };
        let sol_change = self.change(&SOL_MINT, public_sol)?;
        let spl_change = match spl_asset {
            Some(asset) => self.change(&asset, public_spl)?,
            None => 0,
        };

        let spl_change_asset = spl_asset.filter(|_| spl_change > 0);
        let has_sol_change = sol_change > 0;
        let output_layout = match self.change_layout {
            ChangeLayout::Padded => PreparedOutputLayout::BothChanges,
            ChangeLayout::Compact => match (spl_change_asset.is_some(), has_sol_change) {
                (true, true) => PreparedOutputLayout::BothChanges,
                (true, false) => PreparedOutputLayout::SplChange,
                (false, true) => PreparedOutputLayout::SolChange,
                (false, false) => PreparedOutputLayout::Recipients,
            },
        };

        let first_nullifier = first_nullifier(&self.inputs)?;
        let mut outputs = Vec::new();
        match spl_change_asset {
            Some(asset) => outputs.push(SppProofOutputUtxo {
                owner_address: Some(self.owner),
                asset,
                amount: spl_change,
                ring_program_id: self.ring_program_id,
                ..Default::default()
            }),
            None if self.change_layout == ChangeLayout::Padded => {
                outputs.push(SppProofOutputUtxo {
                    owner_tag: Some(self.owner.signing_pubkey.confidential_view_tag()?),
                    ..Default::default()
                })
            }
            None => {}
        }
        if has_sol_change {
            outputs.push(SppProofOutputUtxo {
                owner_address: Some(self.owner),
                asset: SOL_MINT,
                amount: sol_change,
                ring_program_id: self.ring_program_id,
                ..Default::default()
            });
        } else if self.change_layout == ChangeLayout::Padded {
            outputs.push(SppProofOutputUtxo {
                owner_tag: Some(self.owner.signing_pubkey.confidential_view_tag()?),
                ..Default::default()
            });
        }

        for recipient in &self.recipients {
            outputs.push(SppProofOutputUtxo {
                owner_address: Some(recipient.address),
                asset: recipient.asset,
                amount: recipient.amount,
                ring_program_id: match recipient.ring {
                    RecipientRing::OfTransfer => self.ring_program_id,
                    RecipientRing::Default => None,
                },
                ..Default::default()
            });
        }

        // The circuit recomputes every output blinding from the first nullifier,
        // the private seed, and the slot's final physical index, so a compact
        // transfer's change blindings differ from a padded one's.
        assign_output_blindings(&mut outputs, &first_nullifier, &self.blinding_seed)?;

        let shape = resolve_shape(self.shape, self.inputs.len(), outputs.len())?;
        let interface_transfers = self
            .public_transfers
            .iter()
            .copied()
            .map(PublicTransferRequest::settlement_transfer)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(PreparedTransfer {
            owner: self.owner,
            inputs: self.inputs,
            outputs,
            output_blinding_seed: self.blinding_seed,
            first_nullifier,
            shape,
            payer: self.payer,
            interface_transfers,
            output_layout,
            change_layout: self.change_layout,
        })
    }

    fn spl_asset(&self) -> Result<Option<Address>, TransactionError> {
        let mut found: Option<Address> = None;
        let assets = self
            .inputs
            .iter()
            .map(|spend| spend.utxo.asset)
            .chain(self.recipients.iter().map(|recipient| recipient.asset))
            .chain(self.public_transfers.iter().map(|transfer| transfer.asset));
        for asset in assets {
            if asset != SOL_MINT {
                match found {
                    Some(existing) if existing != asset => {
                        return Err(TransactionError::MultiplePublicSplAssets)
                    }
                    _ => found = Some(asset),
                }
            }
        }
        Ok(found)
    }

    fn public_amount(&self, asset: &Address) -> Result<i128, TransactionError> {
        let total = self
            .public_transfers
            .iter()
            .filter(|transfer| &transfer.asset == asset)
            .try_fold(0i128, |total, transfer| {
                let amount = i128::from(transfer.amount);
                let signed = if transfer.is_deposit { amount } else { -amount };
                total
                    .checked_add(signed)
                    .ok_or(TransactionError::PublicTransferOverflow { asset: *asset })
            })?;
        u64::try_from(total.unsigned_abs())
            .map_err(|_| TransactionError::PublicTransferOverflow { asset: *asset })?;
        Ok(total)
    }

    fn input_sum(&self, asset: &Address) -> i128 {
        self.inputs
            .iter()
            .filter(|spend| &spend.utxo.asset == asset)
            .map(|spend| i128::from(spend.utxo.amount))
            .sum()
    }

    fn recipient_sum(&self, asset: &Address) -> i128 {
        self.recipients
            .iter()
            .filter(|recipient| &recipient.asset == asset)
            .map(|recipient| i128::from(recipient.amount))
            .sum()
    }

    fn change(&self, asset: &Address, public: i128) -> Result<u64, TransactionError> {
        let leftover = self
            .input_sum(asset)
            .checked_add(public)
            .and_then(|v| v.checked_sub(self.recipient_sum(asset)))
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
        if leftover < 0 {
            return Err(TransactionError::InsufficientBalance {
                requested: (-leftover) as u64,
                available: 0,
            });
        }
        u64::try_from(leftover).map_err(|_| TransactionError::SelectedBalanceOverflow)
    }
}

impl PublicTransferRequest {
    fn settlement_transfer(self) -> Result<SettlementTransfer, TransactionError> {
        validate_settlement_target(self.asset, self.target)?;
        match self.target {
            SettlementTarget::Sol { user_sol_account } => Ok(SettlementTransfer::Sol {
                is_deposit: self.is_deposit,
                amount: self.amount,
                user_sol_account,
            }),
            SettlementTarget::Spl {
                user_spl_token,
                spl_token_interface,
            } => Ok(SettlementTransfer::Spl {
                mint: self.asset,
                is_deposit: self.is_deposit,
                amount: self.amount,
                user_spl_token,
                spl_token_interface,
            }),
        }
    }
}

fn validate_settlement_target(
    asset: Address,
    target: SettlementTarget,
) -> Result<(), TransactionError> {
    let matches = matches!(
        (asset == SOL_MINT, target),
        (true, SettlementTarget::Sol { .. }) | (false, SettlementTarget::Spl { .. })
    );
    if matches {
        Ok(())
    } else {
        Err(TransactionError::SettlementTargetMismatch { asset })
    }
}

impl PreparedTransfer {
    pub fn change_layout(&self) -> ChangeLayout {
        self.change_layout
    }

    pub fn finalize(
        self,
        tx_viewing_pk: P256Pubkey,
        salt: [u8; SALT_LEN],
        slots: Vec<Option<MessageData>>,
    ) -> Result<SppProofInputs, TransactionError> {
        self.finalize_inner(tx_viewing_pk, salt, slots, false)
    }

    fn finalize_inner(
        self,
        tx_viewing_pk: P256Pubkey,
        salt: [u8; SALT_LEN],
        slots: Vec<Option<MessageData>>,
        allow_p256_sender: bool,
    ) -> Result<SppProofInputs, TransactionError> {
        let PreparedTransfer {
            owner,
            mut inputs,
            mut outputs,
            output_blinding_seed,
            first_nullifier,
            shape,
            payer,
            interface_transfers,
            output_layout,
            ..
        } = self;

        // The sender owns every change position; its resolved tag is the owner
        // view tag folded into the proof's owner-tag chain. The wire tag is the
        // most compact form that resolves to it: `Account(0)` when the
        // Ed25519 owner is the fee payer, otherwise `Inline`.
        let (sender_tag, sender_resolved) =
            sender_owner_tag(&owner.signing_pubkey, &payer, allow_p256_sender)?;

        // Dummy slots must name a participant already bound to real transaction
        // content. The transaction author is not necessarily an input owner and
        // may have no real change output, so use the first real input signer.
        let dummy_owner_tag = inputs
            .iter()
            .find(|input| !input.is_dummy())
            .ok_or(TransactionError::NoInputs)?
            .utxo
            .owner
            .confidential_view_tag()?;
        for output in outputs.iter_mut().filter(|output| output.is_dummy()) {
            output.owner_tag = Some(dummy_owner_tag);
        }

        let dummy_recipient_count = shape.n_outputs().saturating_sub(outputs.len());
        for _ in 0..dummy_recipient_count {
            let output_index =
                u32::try_from(outputs.len()).map_err(|_| TransactionError::TooManyOutputs)?;
            outputs.push(SppProofOutputUtxo {
                blinding: derive_transact_output_blinding(
                    &first_nullifier,
                    &output_blinding_seed,
                    output_index,
                )?,
                owner_tag: Some(dummy_owner_tag),
                ..Default::default()
            });
        }
        while inputs.len() < shape.n_inputs() {
            inputs.push(SppProofInputUtxo::new_dummy());
        }

        // Length-matched random ciphertext for every position without a real
        // encoding: padded slots and zero-value change slots.
        let dummy_len = if slots.iter().any(|slot| slot.is_none()) || dummy_recipient_count > 0 {
            let throwaway = ViewingKey::new();
            dummy_ciphertext_len(&throwaway, throwaway.pubkey(), salt)?
        } else {
            0
        };

        // 1:1 output assembly. Every published slot carries its own ciphertext.
        // Change positions keep the compact sender tag; recipient positions take
        // the inline tag of their ciphertext; padded/zero positions carry a
        // length-matched random ciphertext under their padded tag.
        let mut transact_outputs = Vec::with_capacity(outputs.len());
        let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
        for (position, output) in outputs.iter().enumerate() {
            let utxo_hash = output.hash()?;
            let slot = slots.get(position).and_then(|slot| slot.as_ref());
            let (owner_tag, resolved, data) = if output.is_dummy() {
                (
                    OwnerTag::Inline(dummy_owner_tag),
                    dummy_owner_tag,
                    random_dummy_ciphertext(dummy_len),
                )
            } else if position < output_layout.sender_output_count() {
                let data = match slot {
                    Some(output_data) => output_data.data.clone(),
                    None => random_dummy_ciphertext(dummy_len),
                };
                (sender_tag, sender_resolved, data)
            } else {
                match slot {
                    Some(output_data) => (
                        OwnerTag::Inline(output_data.view_tag),
                        output_data.view_tag,
                        output_data.data.clone(),
                    ),
                    None => {
                        let tag = output.owner_tag.ok_or(TransactionError::MissingOutput)?;
                        (
                            OwnerTag::Inline(tag),
                            tag,
                            random_dummy_ciphertext(dummy_len),
                        )
                    }
                }
            };
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag,
                data: Some(data),
            });
            resolved_owner_tags.push(resolved);
        }

        let external_data = ExternalData::new(
            *tx_viewing_pk.as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
        )
        .with_interface_transfers(interface_transfers)?;

        Ok(SppProofInputs {
            input_utxos: inputs,
            output_utxos: outputs,
            output_blinding_seed,
            external_data,
            payer,
        })
    }
}

impl PreparedOutputLayout {
    const fn sender_output_count(self) -> usize {
        match self {
            Self::BothChanges => 2,
            Self::SplChange | Self::SolChange => 1,
            Self::Recipients => 0,
        }
    }
}

/// The sender's output owner tag and its resolved 32-byte value. The resolved
/// value is the full 32-byte address returned by `confidential_view_tag()`;
/// the instruction tag is `Account(0)` when the owner is the fee payer at
/// account index 0, otherwise `Inline` (relayed transfer). Default transact
/// has no P-256 owner rail. A PDA owner follows the Ed25519 arm: identical in
/// every public-data path, and never the fee payer.
fn sender_owner_tag(
    owner_pubkey: &PublicKey,
    payer: &Address,
    allow_p256_sender: bool,
) -> Result<(OwnerTag, [u8; 32]), TransactionError> {
    let resolved = owner_pubkey.confidential_view_tag()?;
    let tag = match owner_pubkey.curve()? {
        Curve::P256 if allow_p256_sender => OwnerTag::Inline(resolved),
        Curve::P256 => return Err(TransactionError::P256TransactUnsupported),
        Curve::Ed25519 | Curve::Pda => {
            if resolved == payer.to_bytes() {
                OwnerTag::Account(0)
            } else {
                OwnerTag::Inline(resolved)
            }
        }
    };
    Ok((tag, resolved))
}

/// Random `len` bytes for a dummy output slot.
fn random_dummy_ciphertext(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    OsRng.fill_bytes(&mut data);
    data
}

/// The exact ciphertext byte length of a real confidential slot, derived by
/// encoding a throwaway output through the same path. This keeps dummy slots
/// byte-length-indistinguishable from real ones without pinning a brittle constant.
fn dummy_ciphertext_len(
    tx: &ViewingKey,
    throwaway_pubkey: P256Pubkey,
    salt: [u8; SALT_LEN],
) -> Result<usize, TransactionError> {
    let output_data = Confidential::encode_plaintext(
        &ConfidentialOutputPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 0,
            blinding: random_blinding(),
            ring_program_id: None,
            data: Data::default(),
        },
        [0u8; VIEW_TAG_LEN],
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: throwaway_pubkey,
            salt,
            slot_index: 0,
        },
    )?;
    Ok(output_data.data.len())
}

#[cfg(test)]
mod tests {
    use zolana_keypair::{ShieldedKeypair, SigningKey};

    use super::*;

    fn sol_transfer(amount: u64) -> ConfidentialTransfer {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let recipient = ShieldedKeypair::new_ed25519().unwrap();
        let input = SppProofInputUtxo::new(
            crate::Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: None,
                data: Data::default(),
            },
            &sender,
        );
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().unwrap(),
            vec![input],
            Address::default(),
        );
        transfer
            .send(&recipient.shielded_address().unwrap(), SOL_MINT, amount)
            .unwrap();
        transfer
    }

    #[test]
    fn ring_binding_covers_change_and_every_send_in_any_order() {
        let ring = Address::new_from_array([5u8; 32]);
        let mut transfer = sol_transfer(4)
            .with_compact_change()
            .with_ring_program_id(ring);
        let inside = ShieldedKeypair::new_ed25519().unwrap();
        let outside = ShieldedKeypair::new_ed25519().unwrap();
        transfer
            .send(&inside.shielded_address().unwrap(), SOL_MINT, 1)
            .unwrap();
        transfer
            .send_default_ring(&outside.shielded_address().unwrap(), SOL_MINT, 1)
            .unwrap();
        let prepared = transfer.prepare().unwrap();
        let rings: Vec<Option<Address>> = prepared
            .outputs
            .iter()
            .map(|output| output.ring_program_id)
            .collect();
        assert_eq!(rings, vec![Some(ring), Some(ring), Some(ring), None]);
        assert_eq!(prepared.outputs[0].amount, 4);
        assert!(sol_transfer(4)
            .prepare()
            .unwrap()
            .outputs
            .iter()
            .all(|output| output.ring_program_id.is_none()));
    }

    /// An ed25519 owner who is also the fee payer at account index 0 is tagged
    /// `Account(0)`; the resolved value is the owner's view tag (the ed25519 key).
    #[test]
    fn sender_tag_is_account_zero_when_owner_is_payer() {
        let pk = SigningKey::from_ed25519_bytes(&[7u8; 32]).pubkey();
        let resolved = pk.confidential_view_tag().unwrap();
        let payer = Address::new_from_array(resolved);
        let (tag, got_resolved) = sender_owner_tag(&pk, &payer, false).unwrap();
        assert_eq!(tag, OwnerTag::Account(0));
        assert_eq!(got_resolved, resolved);
    }

    /// A relayed transfer whose ed25519 owner is not the fee payer falls back to
    /// an inline tag carrying the owner's view tag verbatim.
    #[test]
    fn sender_tag_is_inline_for_relayed_transfer() {
        let pk = SigningKey::from_ed25519_bytes(&[7u8; 32]).pubkey();
        let resolved = pk.confidential_view_tag().unwrap();
        let unrelated_payer = Address::default();
        let (tag, got_resolved) = sender_owner_tag(&pk, &unrelated_payer, false).unwrap();
        assert_eq!(tag, OwnerTag::Inline(resolved));
        assert_eq!(got_resolved, resolved);
    }

    /// Default transact has no P-256 owner rail.
    #[test]
    fn sender_tag_rejects_p256_owner() {
        let pk = SigningKey::new_p256().pubkey();
        assert_eq!(
            sender_owner_tag(&pk, &Address::default(), false),
            Err(TransactionError::P256TransactUnsupported)
        );
    }

    #[test]
    fn ring_p256_sender_tag_is_inline() {
        let pk = SigningKey::new_p256().pubkey();
        let resolved = pk.confidential_view_tag().unwrap();
        assert_eq!(
            sender_owner_tag(&pk, &Address::default(), true),
            Ok((OwnerTag::Inline(resolved), resolved))
        );
    }

    #[test]
    fn compact_change_removes_unused_change_slots() {
        let prepared = sol_transfer(4).with_compact_change().prepare().unwrap();
        assert_eq!(prepared.shape, Shape::IN1_OUT2);
        assert_eq!(prepared.outputs.len(), 2);
        assert_eq!(prepared.outputs[0].amount, 6);
        assert_eq!(prepared.outputs[1].amount, 4);
        assert_eq!(prepared.output_layout.sender_output_count(), 1);
        assert_eq!(prepared.change_layout(), ChangeLayout::Compact);
    }

    #[test]
    fn compact_change_keeps_only_the_recipient_after_a_full_spend() {
        let prepared = sol_transfer(10).with_compact_change().prepare().unwrap();
        assert_eq!(prepared.shape, Shape::IN1_OUT1);
        assert_eq!(prepared.outputs.len(), 1);
        assert_eq!(prepared.outputs[0].amount, 10);
        assert_eq!(prepared.output_layout.sender_output_count(), 0);
    }

    #[test]
    fn padded_change_keeps_both_slots() {
        let prepared = sol_transfer(10).prepare().unwrap();
        assert_eq!(prepared.outputs.len(), 3);
        assert_eq!(prepared.change_layout(), ChangeLayout::Padded);
    }

    #[test]
    fn transfer_accepts_many_same_asset_settlements_up_to_limit() {
        let owner = ShieldedKeypair::new_p256()
            .unwrap()
            .shielded_address()
            .unwrap();
        let mut transfer = ConfidentialTransfer::new(owner, vec![], Address::default());
        for seed in 1..=zolana_interface::MAX_INTERFACE_TRANSFERS {
            let address_seed = u8::try_from(seed).expect("interface transfer index fits u8");
            transfer
                .withdraw(
                    SOL_MINT,
                    1,
                    SettlementTarget::Sol {
                        user_sol_account: Address::new_from_array([address_seed; 32]),
                    },
                )
                .unwrap();
        }
        assert_eq!(
            transfer.public_transfers.len(),
            zolana_interface::MAX_INTERFACE_TRANSFERS
        );
        assert!(matches!(
            transfer.withdraw(
                SOL_MINT,
                1,
                SettlementTarget::Sol {
                    user_sol_account: Address::default(),
                },
            ),
            Err(TransactionError::TooManyInterfaceTransfers {
                got,
                max
            }) if got == zolana_interface::MAX_INTERFACE_TRANSFERS + 1
                && max == zolana_interface::MAX_INTERFACE_TRANSFERS
        ));
    }

    #[test]
    fn transfer_rejects_target_mismatch_and_zero_but_accepts_full_u64() {
        let owner = ShieldedKeypair::new_p256()
            .unwrap()
            .shielded_address()
            .unwrap();
        let mut transfer = ConfidentialTransfer::new(owner, vec![], Address::default());
        assert!(matches!(
            transfer.deposit(
                SOL_MINT,
                1,
                SettlementTarget::Spl {
                    user_spl_token: Address::default(),
                    spl_token_interface: Address::default(),
                },
            ),
            Err(TransactionError::SettlementTargetMismatch { asset: SOL_MINT })
        ));
        assert!(matches!(
            transfer.settle(
                SOL_MINT,
                false,
                0,
                SettlementTarget::Sol {
                    user_sol_account: Address::default(),
                },
            ),
            Err(TransactionError::ZeroInterfaceTransferAmount)
        ));
        transfer
            .withdraw(
                SOL_MINT,
                u64::MAX,
                SettlementTarget::Sol {
                    user_sol_account: Address::default(),
                },
            )
            .expect("full-u64 withdrawal is supported");
        transfer
            .deposit(
                SOL_MINT,
                u64::MAX,
                SettlementTarget::Sol {
                    user_sol_account: Address::new_from_array([1; 32]),
                },
            )
            .expect("full-u64 deposit is supported");
        assert_eq!(
            transfer.public_transfers.first(),
            Some(&PublicTransferRequest {
                asset: SOL_MINT,
                is_deposit: false,
                amount: u64::MAX,
                target: SettlementTarget::Sol {
                    user_sol_account: Address::default(),
                },
            })
        );
        assert_eq!(
            transfer.public_transfers.get(1),
            Some(&PublicTransferRequest {
                asset: SOL_MINT,
                is_deposit: true,
                amount: u64::MAX,
                target: SettlementTarget::Sol {
                    user_sol_account: Address::new_from_array([1; 32]),
                },
            })
        );
    }
}
