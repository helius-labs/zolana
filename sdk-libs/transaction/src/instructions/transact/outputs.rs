use solana_address::Address;
use zolana_interface::N_PUBLIC_SLOTS;
use zolana_keypair::{shielded::ShieldedAddress, Curve};

use super::{pad_input_utxos, ConfidentialTransaction};
use crate::{
    error::TransactionError,
    instructions::transact::shape::{Shape, SPP_SUPPORTED_SHAPES},
    utxo::{SppProofInputUtxo, SppProofOutputUtxo},
    Mint,
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
        self.outputs.push(output);
        Ok(self)
    }

    /// Convert wallet inputs and pad all UTXOs without reordering existing slots.
    ///
    /// Steps:
    /// 1. Reject repeated padding and validate the shape, input count and public
    ///    transfers.
    /// 2. Require at most three assets and calculate change for each one.
    /// 3. Append nonzero change in asset first-use order, using the transaction's ring.
    /// 4. Check output capacity, append output padding and verify balance.
    /// 5. Convert wallet inputs to proof inputs, append dummy inputs and commit
    ///    both vectors. Errors leave the original transaction unchanged.
    pub fn pad_utxos(
        &mut self,
        shape: Shape,
        sender: &ShieldedAddress,
    ) -> Result<&mut Self, TransactionError> {
        // 1. Reject repeated padding and validate the shape and public transfers.
        if self.padded_inputs.is_some() {
            return Err(TransactionError::OutputUtxosAlreadyPadded);
        }
        if !SPP_SUPPORTED_SHAPES.contains(&shape) {
            return Err(TransactionError::UnsupportedShape {
                n_in: shape.n_inputs(),
                n_out: shape.n_outputs(),
            });
        }
        if self.inputs.len() > shape.n_inputs() {
            return Err(TransactionError::TooManyInputs {
                got: self.inputs.len(),
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

        // 4. Check output capacity, append padding and verify balance.
        if outputs.len() > shape.n_outputs() {
            return Err(TransactionError::TooManyOutputsForShape {
                got: outputs.len(),
                max: shape.n_outputs(),
            });
        }
        while outputs.len() < shape.n_outputs() {
            let mut output = SppProofOutputUtxo::new(Mint::SOL, 0, *sender)?;
            output.ring_program_id = self.ring_program_id;
            outputs.push(output);
        }
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

        // 5. Convert wallet inputs, append dummy inputs and commit both vectors.
        let mut inputs = self.inputs.iter().map(SppProofInputUtxo::from).collect();
        pad_input_utxos(&mut inputs, shape)?;
        self.outputs = outputs;
        self.padded_inputs = Some(inputs);
        Ok(self)
    }

    pub(super) fn internal_add_output_utxo(
        &mut self,
        recipient: Recipient,
    ) -> Result<&mut Self, TransactionError> {
        if self.padded_inputs.is_some() {
            return Err(TransactionError::OutputUtxosAlreadyPadded);
        }
        if recipient.address.signing_pubkey.curve()? == Curve::P256 {
            return Err(TransactionError::P256TransactUnsupported);
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
