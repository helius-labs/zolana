use solana_address::Address;
use zolana_interface::N_PUBLIC_SLOTS;
use zolana_keypair::shielded::ShieldedAddress;

use super::{inputs::pad_inputs, ConfidentialTransaction};
use crate::{
    error::TransactionError, instructions::transact::shape::Shape, utxo::SppProofOutputUtxo, Mint,
};

pub struct Recipient {
    pub address: ShieldedAddress,
    pub asset: Mint,
    pub amount: u64,
    pub ring_program_id: Option<Address>,
}

impl ConfidentialTransaction {
    pub fn outputs(&self) -> &[SppProofOutputUtxo] {
        &self.outputs
    }

    pub fn output_tree_id(&self) -> u16 {
        self.output_tree_id
    }

    /// Append the outputs to `output_tree_id`. Without this, they go to the
    /// first real input's [`latest_tree_id`](crate::WalletUtxo::latest_tree_id), else tree 0.
    pub fn with_output_tree_id(mut self, output_tree_id: u16) -> Result<Self, TransactionError> {
        if self.padded_inputs.is_some() {
            return Err(TransactionError::OutputUtxosAlreadyPadded);
        }
        self.output_tree_id = output_tree_id;
        Ok(self)
    }

    pub fn add_output_utxo(
        &mut self,
        output: SppProofOutputUtxo,
    ) -> Result<&mut Self, TransactionError> {
        if self.padded_inputs.is_some() {
            return Err(TransactionError::OutputUtxosAlreadyPadded);
        }
        if output.is_dummy() {
            return Err(TransactionError::OutputWithoutOwner {
                slot_index: self.outputs.len(),
            });
        }
        self.outputs.push(output);
        Ok(self)
    }

    pub fn add_empty_output_utxo(&mut self) -> Result<&mut Self, TransactionError> {
        if self.padded_inputs.is_some() {
            return Err(TransactionError::OutputUtxosAlreadyPadded);
        }
        self.outputs.push(SppProofOutputUtxo::default());
        Ok(self)
    }

    /// Pad all UTXOs without reordering existing slots.
    ///
    /// Steps:
    /// 1. Reject repeated padding and validate the shape, input count and public
    ///    transfers.
    /// 2. Require at most three assets and calculate change for each one.
    /// 3. Append nonzero change in asset first-use order, using the transaction's ring.
    /// 4. Check output capacity, append dummy outputs that publish a
    ///    participant's view tag and verify balance. A transaction naming no
    ///    participant keeps a zero-amount SOL change for the sender.
    /// 5. Append dummy inputs and commit both vectors. Errors leave the
    ///    original transaction unchanged.
    pub fn pad_utxos(
        &mut self,
        shape: Shape,
        sender: &ShieldedAddress,
    ) -> Result<&mut Self, TransactionError> {
        self.pad(shape, sender, false)
    }

    /// Pad like [`Self::pad_utxos`] for a transaction whose outputs a circuit
    /// fixes: no output is added beyond nonzero change. The circuit requires
    /// every published dummy tag to name an owner signer or a real output owner.
    /// With published dummy padding, a transaction naming no such participant
    /// is refused with [`TransactionError::NoDummyOwnerTagParticipant`] instead
    /// of keeping a zero-amount change. Compact padding needs no owner tag.
    pub fn pad_utxos_with_empty_outputs(
        &mut self,
        shape: Shape,
        sender: &ShieldedAddress,
    ) -> Result<&mut Self, TransactionError> {
        self.pad(shape, sender, true)
    }

    fn pad(
        &mut self,
        shape: Shape,
        sender: &ShieldedAddress,
        fixed_outputs: bool,
    ) -> Result<&mut Self, TransactionError> {
        // 1. Reject repeated padding and validate the shape and public transfers.
        if self.padded_inputs.is_some() {
            return Err(TransactionError::OutputUtxosAlreadyPadded);
        }
        if !shape.is_supported() {
            return Err(TransactionError::UnsupportedShape {
                n_in: shape.n_inputs(),
                n_out: shape.n_outputs(),
            });
        }
        if self.inputs.len() + self.addresses.len() > shape.n_inputs() {
            return Err(TransactionError::TooManyInputs {
                got: self.inputs.len() + self.addresses.len(),
                max: shape.n_inputs(),
            });
        }
        self.validate_interface_transfers()?;

        // 2. Validate the asset count and calculate change for each asset.
        let changes = self
            .assets(&self.outputs)?
            .into_iter()
            .map(|asset| Ok((asset, self.change(&asset)?)))
            .collect::<Result<Vec<_>, TransactionError>>()?;

        // 3. Append nonzero change in asset first-use order, using the transaction's ring.
        let mut outputs = self.outputs.clone();
        for (asset, amount) in changes.into_iter().filter(|(_, amount)| *amount > 0) {
            outputs.push(SppProofOutputUtxo {
                owner_address: Some(*sender),
                asset,
                amount,
                ring_program_id: self.ring_program_id,
                ..Default::default()
            });
        }

        // 4. Check output capacity, append dummy outputs and verify balance.
        let dummy_owner_tag = if self.compact_padding {
            None
        } else {
            Some(match self.dummy_owner_tag(&outputs, sender)? {
                Some(tag) => tag,
                // Published padding must name a participant. Fixed outputs
                // cannot add change solely to carry that participant's tag.
                None if fixed_outputs => return Err(TransactionError::NoDummyOwnerTagParticipant),
                None => {
                    outputs.push(SppProofOutputUtxo {
                        owner_address: Some(*sender),
                        asset: Mint::SOL,
                        ring_program_id: self.ring_program_id,
                        ..Default::default()
                    });
                    sender.signing_pubkey.confidential_view_tag()?
                }
            })
        };
        if outputs.len() > shape.n_outputs() {
            return Err(TransactionError::TooManyOutputsForShape {
                got: outputs.len(),
                max: shape.n_outputs(),
            });
        }
        // Explicitly empty slots use the same padding mode as appended slots.
        for output in outputs.iter_mut().filter(|output| output.is_dummy()) {
            if self.compact_padding {
                output.compact = true;
                output.owner_tag = None;
            } else if !output.compact && output.owner_tag.is_none() {
                output.owner_tag = dummy_owner_tag;
            }
        }
        outputs.resize(
            shape.n_outputs(),
            if self.compact_padding {
                SppProofOutputUtxo {
                    ring_program_id: self.ring_program_id,
                    compact: true,
                    ..Default::default()
                }
            } else {
                SppProofOutputUtxo {
                    ring_program_id: self.ring_program_id,
                    owner_tag: dummy_owner_tag,
                    ..Default::default()
                }
            },
        );
        for asset in self.assets(&outputs)? {
            let available = self
                .input_sum(&asset)
                .checked_add(self.public_amount(&asset)?)
                .ok_or(TransactionError::SelectedBalanceOverflow)?;
            let paid: i128 = outputs
                .iter()
                .filter(|output| output.asset == asset)
                .map(|output| i128::from(output.amount))
                .sum();
            if available != paid {
                return Err(TransactionError::TransactionDoesNotBalance { asset: asset.asset });
            }
        }

        // 5. Append dummy inputs and commit both vectors.
        let mut inputs = self
            .addresses
            .iter()
            .cloned()
            .chain(self.inputs.iter().cloned())
            .collect();
        pad_inputs(&mut inputs, shape, self.compact_padding)?;
        self.outputs = outputs;
        self.padded_inputs = Some(inputs);
        Ok(self)
    }

    fn dummy_owner_tag(
        &self,
        outputs: &[SppProofOutputUtxo],
        sender: &ShieldedAddress,
    ) -> Result<Option<[u8; 32]>, TransactionError> {
        if let Some(tag) = self.named_input_owner_tag()? {
            return Ok(Some(tag));
        }
        let owners = || outputs.iter().filter_map(|output| output.owner_address);
        let Some(owner) = owners()
            .find(|owner| owner.signing_pubkey == sender.signing_pubkey)
            .or_else(|| owners().next())
        else {
            return Ok(None);
        };
        Ok(Some(owner.signing_pubkey.confidential_view_tag()?))
    }

    /// The first owner signer other than the fee payer, in input slot order:
    /// address owners, then real input owners. Address owners authorize SPP
    /// like input owners, so they are owner signers too. A dummy output may
    /// name any owner signer; skipping the payer keeps a self-paid
    /// transaction's dummies naming its change output.
    fn named_input_owner_tag(&self) -> Result<Option<[u8; 32]>, TransactionError> {
        let payer = self.payer.to_bytes();
        let address_owners = self.addresses.iter().map(|address| &address.utxo.owner);
        let input_owners = self.inputs.iter().map(|input| &input.utxo.owner);
        for owner in address_owners
            .chain(input_owners)
            .filter(|owner| !owner.is_zero())
        {
            let tag = owner.confidential_view_tag()?;
            if tag != payer {
                return Ok(Some(tag));
            }
        }
        Ok(None)
    }

    pub(super) fn internal_add_output_utxo(
        &mut self,
        recipient: Recipient,
    ) -> Result<&mut Self, TransactionError> {
        if self.padded_inputs.is_some() {
            return Err(TransactionError::OutputUtxosAlreadyPadded);
        }
        if recipient.address.signing_pubkey.is_zero() {
            return Err(TransactionError::ZeroRecipientOwner);
        }
        self.outputs.push(SppProofOutputUtxo {
            owner_address: Some(recipient.address),
            asset: recipient.asset,
            amount: recipient.amount,
            ring_program_id: recipient.ring_program_id,
            ..Default::default()
        });
        Ok(self)
    }

    pub(super) fn assets(
        &self,
        outputs: &[SppProofOutputUtxo],
    ) -> Result<Vec<Mint>, TransactionError> {
        let mut assets: Vec<Mint> = Vec::with_capacity(N_PUBLIC_SLOTS);
        let seen = self
            .inputs
            .iter()
            .filter(|input| input.utxo.amount > 0)
            .map(|input_utxo| input_utxo.utxo.asset)
            .chain(
                outputs
                    .iter()
                    .filter(|output| output.amount > 0)
                    .map(|output| output.asset),
            )
            .chain(self.public_transfers.iter().map(|transfer| transfer.asset));
        for asset in seen {
            if !assets.contains(&asset) {
                assets.push(asset);
            }
        }
        if assets.len() > N_PUBLIC_SLOTS {
            return Err(TransactionError::TooManyAssets {
                got: assets.len(),
                max: N_PUBLIC_SLOTS,
            });
        }
        Ok(assets)
    }

    pub(super) fn input_sum(&self, asset: &Mint) -> i128 {
        self.inputs
            .iter()
            .filter(|input_utxo| &input_utxo.utxo.asset == asset)
            .map(|input_utxo| i128::from(input_utxo.utxo.amount))
            .sum()
    }

    pub(super) fn change(&self, asset: &Mint) -> Result<u64, TransactionError> {
        let public = self.public_amount(asset)?;
        let declared_output_sum: i128 = self
            .outputs
            .iter()
            .filter(|output| &output.asset == asset)
            .map(|output| i128::from(output.amount))
            .sum();
        let leftover = self
            .input_sum(asset)
            .checked_add(public)
            .and_then(|v| v.checked_sub(declared_output_sum))
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
