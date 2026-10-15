//! Per-mint outflow accounting and the record transition the policy proof commits.

use solana_address::Address;
use zolana_client::Shape;
use zolana_interface::instruction::MessageData;
use zolana_keypair::{random_blinding, PublicKey, ShieldedAddress, ViewingKey};
use zolana_ring_client::{find_counters_message, open_counters, seal_counters};
use zolana_ring_policy::{
    ListNamespace, Member, SpendCounters, SpendRecord, VelocityRow, MAX_VELOCITY_ASSETS,
    POLICY_INPUT_SLOTS, POLICY_OUTPUT_SLOTS,
};
use zolana_transaction::{
    instructions::transact::SppProofOutputUtxo,
    keys::{ShieldedKeys, TransactionKeyRequest},
    utxo::{derive_transact_output_blinding, SppProofInputUtxo},
    Data, Mint, TransactionError, Utxo,
};

use crate::{
    entry::zero_nullifier_key, LiveSpendRecord, RingError, RingIdentity, SpendRecordProofInput,
    VelocityProofInput,
};

/// Slots before a window boundary in which no windowed proof is built.
pub const WINDOW_GUARD_SLOTS: u64 = 64;

/// The window `slot` lies in, refused while too few slots remain for the proof to land.
pub(crate) fn window_index(slot: u64, window_slots: u64) -> Result<u64, RingError> {
    let left = window_slots - slot % window_slots;
    if left <= WINDOW_GUARD_SLOTS.min(window_slots / 2) {
        return Err(RingError::WindowClosing {
            resumes_at: slot + left,
        });
    }
    Ok(slot / window_slots)
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

pub(crate) struct VelocityContext {
    pub namespace: Address,
    pub owner: ListNamespace,
    pub identity: RingIdentity,
    pub address_tree_id: u16,
    pub window_slots: u64,
    pub rows: Vec<VelocityRow>,
}

pub(crate) struct VelocityFacts {
    pub context: VelocityContext,
    pub window_index: u64,
    pub live: LiveSpendRecord,
    /// `None` for an expired record, the circuit opens only its commitment.
    pub counters: Option<SpendCounters>,
}

impl VelocityContext {
    pub(crate) fn facts(
        self,
        sender: &(dyn ShieldedKeys + Send + Sync),
        live: LiveSpendRecord,
        slot: u64,
    ) -> Result<VelocityFacts, RingError> {
        let window_index = window_index(slot, self.window_slots)?;
        // A future record cannot reset, an expired one resets without opening counters.
        let counters = match live.record.window.cmp(&window_index) {
            core::cmp::Ordering::Greater => return Err(RingError::SpendRecordFromFutureWindow),
            core::cmp::Ordering::Less => None,
            core::cmp::Ordering::Equal => Some(self.counters(sender, &live)?),
        };
        Ok(VelocityFacts {
            context: self,
            window_index,
            live,
            counters,
        })
    }

    /// The counters of the live record, trusted once they reproduce its commitment.
    fn counters(
        &self,
        sender: &(dyn ShieldedKeys + Send + Sync),
        live: &LiveSpendRecord,
    ) -> Result<SpendCounters, RingError> {
        let counters = if live.record.version == 0 {
            SpendCounters::EMPTY
        } else {
            let origin = &live.origin;
            let unknown = || RingError::SpendCountersUnknown;
            let message = find_counters_message(&origin.messages, self.namespace.as_array())
                .ok()
                .flatten()
                .ok_or_else(unknown)?;
            let tx_key = transaction_key(sender, origin.first_nullifier)?;
            open_counters(&message.data, origin.salt.ok_or_else(unknown)?, &tx_key)
                .map_err(|_| unknown())?
        };
        if counters.commitment()? != live.record.counters_commitment {
            return Err(RingError::SpendCountersUnknown);
        }
        Ok(counters)
    }
}

pub(crate) struct Outflows<'a> {
    pub sender: Member,
    pub ring: Address,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
}

impl Outflows<'_> {
    /// Inputs of the mint less the sender's change inside the ring, as the circuit sums them.
    fn outflow(&self, asset: &[u8; 32]) -> Result<u64, RingError> {
        let mut inflow: u128 = 0;
        for input in self.inputs.iter().filter(|input| !input.is_dummy()) {
            if Member::asset(&input.utxo.asset.asset)?.as_bytes() == asset {
                inflow += u128::from(input.utxo.amount);
            }
        }
        let mut change: u128 = 0;
        for output in self.outputs {
            let Some(address) = output.owner_address.as_ref() else {
                continue;
            };
            if Member::asset(&output.asset.asset)?.as_bytes() == asset
                && address.signing_pubkey.owner_proof_input_hash()? == *self.sender.as_bytes()
                && output.ring_program_id == Some(self.ring)
            {
                change += u128::from(output.amount);
            }
        }
        let outflow = inflow
            .checked_sub(change)
            .ok_or(RingError::VelocityChangeExceedsInflow { asset: *asset })?;
        u64::try_from(outflow).map_err(|_| RingError::VelocityOverflow)
    }
}

#[derive(Debug)]
pub(crate) struct RowCharges {
    pub rows: [VelocityRow; MAX_VELOCITY_ASSETS],
    pub row_count: u8,
    pub spent: [u64; MAX_VELOCITY_ASSETS],
    pub approval_required: bool,
}

/// A row without a cap keeps a zero counter, it only asks the co-signer.
pub(crate) fn charge(
    rows: &[VelocityRow],
    outflows: &Outflows<'_>,
    previous: Option<&SpendCounters>,
) -> Result<RowCharges, RingError> {
    let mut charges = RowCharges {
        rows: [VelocityRow::EMPTY; MAX_VELOCITY_ASSETS],
        row_count: rows.len() as u8,
        spent: [0; MAX_VELOCITY_ASSETS],
        approval_required: false,
    };
    for (index, row) in rows.iter().enumerate() {
        let outflow = outflows.outflow(&row.asset)?;
        charges.rows[index] = *row;
        charges.approval_required |= row.cosign_above != 0 && outflow > row.cosign_above;
        if row.cap == 0 {
            continue;
        }
        let previous = previous.map_or(0, |counters| counters.spent(&row.asset));
        let spent = previous
            .checked_add(outflow)
            .ok_or(RingError::VelocityOverflow)?;
        if spent > row.cap {
            return Err(RingError::VelocityCapExceeded {
                asset: row.asset,
                cap: row.cap,
                spent,
            });
        }
        charges.spent[index] = spent;
    }
    Ok(charges)
}

impl VelocityProofInput {
    /// Rows without a window carry the charges, no record accompanies them.
    pub(crate) fn per_transfer(charges: &RowCharges, identity: RingIdentity) -> Self {
        Self {
            rows: charges.rows,
            row_count: charges.row_count,
            approval_required: charges.approval_required,
            ..Self::off(identity)
        }
    }
}

pub(crate) struct VelocityPlan {
    pub input: SppProofInputUtxo,
    pub output: SppProofOutputUtxo,
    pub record_message: MessageData,
    pub counters_message: MessageData,
    pub proof_input: VelocityProofInput,
    pub shape: Shape,
    /// The record's output slot, after the money slots and ahead of the compact padding.
    pub record_slot: usize,
}

pub(crate) struct RecordSpend<'a> {
    pub outflows: Outflows<'a>,
    pub tx_viewing_key: &'a ViewingKey,
    pub salt: [u8; 16],
    pub first_nullifier: [u8; 32],
    pub output_blinding_seed: [u8; 32],
    /// The real money slots, the record follows the last real output.
    pub money_shape: Shape,
}

impl VelocityFacts {
    pub(crate) fn plan(&self, spend: RecordSpend<'_>) -> Result<Box<VelocityPlan>, RingError> {
        let context = &self.context;
        let shape = record_shape(spend.money_shape)?;
        let record_slot = spend.money_shape.n_outputs();
        let charges = charge(&context.rows, &spend.outflows, self.counters.as_ref())?;
        let mut next = SpendCounters::EMPTY;
        next.salt = random_blinding();
        for (index, row) in context.rows.iter().enumerate() {
            next.assets[index] = row.asset;
            next.spent[index] = charges.spent[index];
        }
        let spent = &self.live.record;
        let successor = SpendRecord {
            member: spent.member,
            version: spent
                .version
                .checked_add(1)
                .ok_or(RingError::VelocityOverflow)?,
            window: self.window_index,
            counters_commitment: next.commitment()?,
            blinding: derive_transact_output_blinding(
                &spend.first_nullifier,
                &spend.output_blinding_seed,
                u32::try_from(record_slot).map_err(|_| RingError::PolicyShapeUnsupported)?,
            )?,
        };
        let address = context
            .owner
            .spend_address(&spent.member, context.address_tree_id)?;
        let spent_data_hash = spent.data_hash(&address)?;
        let zero_nullifier = zero_nullifier_key();
        let nullifier_pubkey = zero_nullifier.pubkey()?;
        let input_utxo = Utxo {
            owner: PublicKey::from_pda(&context.namespace),
            asset: Mint::SOL,
            amount: 0,
            blinding: spent.blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let utxo_hash = input_utxo.hash(
            &nullifier_pubkey,
            &spent_data_hash,
            &[0; 32],
            self.live.tree_id,
        )?;
        let input = SppProofInputUtxo {
            nullifier: zero_nullifier.nullifier(&utxo_hash, &spent.blinding)?,
            utxo: input_utxo,
            nullifier_pubkey,
            utxo_hash,
            data_hash: Some(spent_data_hash),
            ring_data_hash: None,
            tree_id: self.live.tree_id,
            leaf_index: self.live.leaf_index,
            cache_slot: None,
            compact: false,
        };
        let output = SppProofOutputUtxo {
            asset: Mint::SOL,
            blinding: successor.blinding,
            data_hash: Some(successor.data_hash(&address)?),
            owner_address: Some(ShieldedAddress::for_pda(
                &context.namespace,
                nullifier_pubkey,
                spend.tx_viewing_key.pubkey(),
            )),
            owner_tag: Some(context.namespace.to_bytes()),
            ..Default::default()
        };
        let opened = self.counters.unwrap_or(SpendCounters::EMPTY);
        Ok(Box::new(VelocityPlan {
            input,
            output,
            record_message: MessageData {
                view_tag: zolana_ring_policy::spend_record_message_tag(
                    context.namespace.as_array(),
                )?,
                data: successor.to_output_data().to_vec(),
            },
            counters_message: MessageData {
                view_tag: context.namespace.to_bytes(),
                data: seal_counters(
                    spend.tx_viewing_key,
                    &spend.tx_viewing_key.pubkey(),
                    spend.salt,
                    &next,
                )?,
            },
            proof_input: VelocityProofInput {
                window_slots: context.window_slots,
                window_index: self.window_index,
                record: SpendRecordProofInput {
                    version: spent.version,
                    window: spent.window,
                    commitment: spent.counters_commitment,
                    salt: opened.salt,
                    assets: opened.assets,
                    spent: opened.spent,
                    next_salt: next.salt,
                },
                ..VelocityProofInput::per_transfer(&charges, context.identity)
            },
            shape,
            record_slot,
        }))
    }
}

/// The smallest supported shape with one slot beyond the money on each side.
pub(crate) fn record_shape(money: Shape) -> Result<Shape, RingError> {
    zolana_client::SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| {
            shape.n_inputs() <= POLICY_INPUT_SLOTS && shape.n_outputs() <= POLICY_OUTPUT_SLOTS
        })
        .find(|shape| shape.n_inputs() > money.n_inputs() && shape.n_outputs() > money.n_outputs())
        .ok_or(RingError::PolicyShapeUnsupported)
}
