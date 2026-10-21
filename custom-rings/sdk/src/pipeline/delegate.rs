use std::collections::BTreeSet;

use custom_ring_interface::RingMode;
use solana_address::Address;
use zolana_client::{AsyncIndexer, AsyncRpc, AsyncZolanaClient};
use zolana_interface::shape::{ring_authority_shapes, Shape};
use zolana_keypair::{NullifierKey, ShieldedAddress, ViewingKey};
use zolana_ring_transaction::RingOutputRail;
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, SppProofOutputUtxo},
    select_spend_where, AssetRegistry, TransactionError, WalletUtxo,
};

use super::{
    packed_or_delivered, sealed, Rail, RailKind, RingTransfer, Spend, Staged, TransferAuthority,
};
use crate::{projection::retry_projection_lag, CustomRing, CustomRingConfig, RingError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegateOutput {
    pub recipient: ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegatePayment {
    pub recipient: ShieldedAddress,
    pub amount: u64,
}

#[must_use = "select the notes of the move"]
pub struct DelegateMove<'a> {
    pub ring: CustomRing,
    pub delegate: Address,
    pub payer: Address,
    pub source: ShieldedAddress,
    pub source_nullifier_key: &'a NullifierKey,
    /// The source's notes on any tree.
    pub notes: &'a [WalletUtxo],
    pub mint: Address,
    /// The change returns to the source.
    pub payments: Vec<DelegatePayment>,
    pub assets: &'a AssetRegistry,
}

/// The delegate moves a member's notes with the recovered key, the member does not sign.
pub struct Delegated<'a> {
    delegate: Address,
    payer: Address,
    source: ShieldedAddress,
    source_key: NullifierKey,
    inputs: Vec<WalletUtxo>,
    outputs: Vec<DelegateOutput>,
    output_tree_id: Option<u16>,
    shape: Option<Shape>,
    assets: Option<&'a AssetRegistry>,
}

pub struct DelegateTransferInput<'a> {
    pub ring: CustomRing,
    /// Signs the transaction beside the payer.
    pub delegate: Address,
    pub payer: Address,
    /// The member whose notes move, its change returns to it.
    pub source: ShieldedAddress,
    /// Recovered from escrow, the proof spends the member's notes with it.
    pub source_nullifier_key: &'a NullifierKey,
    pub inputs: Vec<WalletUtxo>,
    pub outputs: Vec<DelegateOutput>,
}

pub type DelegateTransfer<'a> = RingTransfer<Delegated<'a>>;

impl sealed::Sealed for Delegated<'_> {}

impl Rail for Delegated<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Delegated(self)
    }
}

impl<'a> RingTransfer<Delegated<'a>> {
    pub fn new(input: DelegateTransferInput<'_>) -> Self {
        Self {
            ring: input.ring,
            rail: Delegated {
                delegate: input.delegate,
                payer: input.payer,
                source: input.source,
                source_key: input.source_nullifier_key.clone(),
                inputs: input.inputs,
                outputs: input.outputs,
                output_tree_id: None,
                shape: None,
                assets: None,
            },
        }
    }

    /// Unset, the first input's `latest_tree_id` takes the outputs, else tree 0.
    #[must_use = "use the updated move"]
    pub fn with_output_tree_id(mut self, tree_id: u16) -> Self {
        self.rail.output_tree_id = Some(tree_id);
        self
    }

    #[must_use = "use the updated move"]
    pub fn with_assets(mut self, assets: &'a AssetRegistry) -> Self {
        self.rail.assets = Some(assets);
        self
    }

    /// Unset, staging pads to the cheapest supported shape.
    pub fn with_shape(mut self, shape: Shape) -> Result<Self, RingError> {
        if !shape.is_ring_authority() {
            return Err(RingError::ShapeUnkeyed { rail: "delegate" });
        }
        self.rail.shape = Some(shape);
        Ok(self)
    }
}

impl<'a> DelegateMove<'a> {
    /// The fewest notes of one tree funding the payments whose assembled move fits one transaction.
    pub async fn select<P: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<DelegateTransfer<'a>, RingError> {
        let amount = self
            .payments
            .iter()
            .try_fold(0u64, |total, payment| total.checked_add(payment.amount))
            .ok_or(RingError::OutflowOverflow)?;
        if amount == 0 {
            return Err(TransactionError::ZeroSpendAmount.into());
        }
        // The shape holds a change slot, the selection may leave none.
        let outputs = self.payments.len() + 1;
        let shapes = || ring_authority_shapes().filter(move |shape| shape.n_outputs() >= outputs);
        let unkeyed = || RingError::ShapeUnkeyed { rail: "delegate" };
        let max_inputs = shapes()
            .map(|shape| shape.n_inputs())
            .max()
            .ok_or_else(unkeyed)?;
        let trees: BTreeSet<u16> = self.notes.iter().map(|note| note.tree_id).collect();
        let mut candidates: Vec<_> = trees
            .into_iter()
            .filter_map(|tree| {
                let notes = select_spend_where(self.notes, self.mint, amount, max_inputs, |note| {
                    self.spends(note, tree)
                })
                .ok()?;
                let total: u128 = notes.iter().map(|note| u128::from(note.utxo.amount)).sum();
                Some(((notes.len(), total, tree), notes))
            })
            .collect();
        candidates.sort_unstable_by_key(|(order, _)| *order);
        let mut oversized = None;
        for ((count, _, _), notes) in candidates {
            let shape = shapes()
                .find(|shape| shape.n_inputs() >= count)
                .ok_or_else(unkeyed)?;
            let transfer = self.transfer(notes).with_shape(shape)?;
            match retry_projection_lag(|| transfer.assemble(client)).await {
                Ok(_) => return Ok(transfer),
                Err(
                    error @ (RingError::TransactionTooLarge { .. }
                    | RingError::TooManyAddresses { .. }),
                ) => {
                    oversized.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(oversized.unwrap_or(RingError::DelegateMoveUnfunded {
            mint: self.mint,
            amount,
            max_inputs,
        }))
    }

    fn spends(&self, note: &WalletUtxo, tree: u16) -> bool {
        note.tree_id == tree
            && note.utxo.owner == self.source.signing_pubkey
            && note.utxo.ring_program_id == Some(self.ring.program_id())
    }

    fn transfer(&self, notes: Vec<WalletUtxo>) -> DelegateTransfer<'a> {
        DelegateTransfer::new(DelegateTransferInput {
            ring: self.ring,
            delegate: self.delegate,
            payer: self.payer,
            source: self.source,
            source_nullifier_key: self.source_nullifier_key,
            inputs: notes,
            outputs: self
                .payments
                .iter()
                .map(|payment| DelegateOutput {
                    recipient: payment.recipient,
                    asset: self.mint,
                    amount: payment.amount,
                })
                .collect(),
        })
        .with_assets(self.assets)
    }
}

impl Delegated<'_> {
    pub(super) async fn stage<R: AsyncRpc + ?Sized>(
        &self,
        ring: CustomRing,
        _client: &R,
        config: &CustomRingConfig,
    ) -> Result<Staged<'_>, RingError> {
        match config.delegate {
            None => return Err(RingError::MissingDelegate),
            Some(stored) if stored != self.delegate => {
                return Err(custom_ring_interface::CustomRingError::UnauthorizedDelegate.into())
            }
            Some(_) => {}
        }
        if config.mode != RingMode::Registry || !config.has_policy {
            return Err(RingError::DelegateRequiresEscrow);
        }
        if self.source_key.pubkey()? != self.source.nullifier_pubkey {
            return Err(RingError::NullifierKeyMismatch);
        }
        if let Some(index) = self
            .inputs
            .iter()
            .position(|input| input.utxo.owner != self.source.signing_pubkey)
        {
            return Err(RingError::MixedOwners { index });
        }
        let assets = self.assets.ok_or(RingError::MissingAssetRegistry)?;
        let program = ring.program_id();
        let mut transaction =
            ConfidentialTransaction::new_with_ring(self.inputs.clone(), self.payer, program)?;
        if let Some(tree_id) = self.output_tree_id {
            transaction = transaction.with_output_tree_id(tree_id)?;
        }
        for output in &self.outputs {
            transaction.add_output_utxo(
                SppProofOutputUtxo::new(
                    assets.mint(&output.asset)?,
                    output.amount,
                    output.recipient,
                )?
                .with_ring_program_id(program),
            )?;
        }
        match self.shape {
            Some(shape) => transaction.pad_utxos(shape, &self.source)?,
            None => transaction.pad_to_canonical_shape(&self.source)?,
        };
        let delivery = packed_or_delivered(transaction.outputs().len(), "delegate")?;
        // The delegate holds no viewing key of the member, a fresh transaction key seals the move.
        let rail = RingOutputRail::new(ViewingKey::new(), delivery);
        let proof_inputs = rail.encrypt(transaction, &self.source)?;
        let shape = Shape::new(
            proof_inputs.input_utxos.len(),
            proof_inputs.output_utxos.len(),
        );
        if !shape.is_ring_authority() {
            return Err(RingError::ShapeUnkeyed { rail: "delegate" });
        }
        Ok(Staged {
            proof_inputs,
            rail,
            sender: self.source,
            authority: TransferAuthority {
                owner: Some(self.source_key.clone()),
            },
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            spend: Spend::Delegate {
                delegate: self.delegate,
            },
        })
    }
}
