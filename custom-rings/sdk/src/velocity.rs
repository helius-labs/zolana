//! The record slots a velocity transfer adds and the witness the circuit charges them with.

use rand::{rngs::OsRng, RngCore};
use solana_address::Address;
use zolana_client::Shape;
use zolana_interface::instruction::MessageData;
use zolana_keypair::{NullifierKey, PublicKey, ShieldedAddress, ViewingKey, ViewingKeyTrait};
use zolana_ring_policy::{
    ring_id_field, ListNamespace, Member, SpendCounters, SpendRecord, VelocityRow,
    MAX_VELOCITY_ASSETS,
};
use zolana_transaction::{
    instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo},
    utxo::derive_transact_output_blinding,
    Data, Utxo, SOL_MINT,
};

use zolana_ring_client::{
    counters_message, decrypt_counters, encrypt_counters, find_counters_message,
};

use crate::{
    instructions::spend::LiveSpendRecord,
    instructions::transact::{SpendRecordWitness, VelocityWitness},
    TransferError,
};

pub(crate) struct VelocityFacts {
    pub namespace: Address,
    pub owner: ListNamespace,
    pub entries_tree_id: u16,
    pub window_slots: u64,
    pub rows: Vec<VelocityRow>,
    pub window_index: u64,
    pub live: LiveSpendRecord,
    /// `None` for an expired record, the circuit opens only its commitment.
    pub counters: Option<SpendCounters>,
}

pub(crate) struct VelocityContext<'a> {
    pub namespace: Address,
    pub owner: ListNamespace,
    pub entries_tree_id: u16,
    pub window_slots: u64,
    pub rows: Vec<VelocityRow>,
    pub sender: &'a (dyn ViewingKeyTrait + Send + Sync),
}

impl VelocityContext<'_> {
    pub(crate) fn facts(
        self,
        live: LiveSpendRecord,
        slot: u64,
    ) -> Result<VelocityFacts, TransferError> {
        let window_index = slot / self.window_slots;
        let counters = VelocityFacts::recover_counters(
            &live,
            window_index,
            self.namespace.as_array(),
            self.sender,
        )?;
        Ok(VelocityFacts {
            namespace: self.namespace,
            owner: self.owner,
            entries_tree_id: self.entries_tree_id,
            window_slots: self.window_slots,
            rows: self.rows,
            window_index,
            live,
            counters,
        })
    }
}

impl VelocityFacts {
    pub(crate) fn recover_counters(
        live: &LiveSpendRecord,
        window_index: u64,
        namespace: &[u8; 32],
        sender: &(dyn ViewingKeyTrait + Send + Sync),
    ) -> Result<Option<SpendCounters>, TransferError> {
        if live.record.window != window_index {
            return Ok(None);
        }
        let counters = if live.record.version == 0 {
            SpendCounters::zero(&[])
        } else {
            let message = find_counters_message(&live.origin.messages, namespace)
                .ok_or(TransferError::SpendCountersUnknown)?;
            let salt = live
                .origin
                .salt
                .ok_or(TransferError::SpendCountersUnknown)?;
            let tx_key = sender.get_transaction_viewing_key(&live.origin.first_nullifier)?;
            decrypt_counters(&tx_key, &message.data, salt)
                .map_err(|_| TransferError::SpendCountersUnknown)?
        };
        if counters
            .commitment()
            .map_err(|_| TransferError::PolicyHashing)?
            != live.record.counters_commitment
        {
            return Err(TransferError::SpendCountersUnknown);
        }
        Ok(Some(counters))
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
    fn outflow(&self, asset: &[u8; 32]) -> Result<u64, TransferError> {
        let mut inflow: u64 = 0;
        for input in self.inputs.iter().filter(|input| !input.is_dummy()) {
            if Member::asset(&input.utxo.asset)
                .map_err(|_| TransferError::PolicyHashing)?
                .as_bytes()
                == asset
            {
                inflow = inflow
                    .checked_add(input.utxo.amount)
                    .ok_or(TransferError::VelocityOverflow)?;
            }
        }
        let mut change: u64 = 0;
        for output in self.outputs {
            let Some(address) = output.owner_address.as_ref() else {
                continue;
            };
            let owner = address
                .signing_pubkey
                .owner_proof_input_hash()
                .map_err(|_| TransferError::PolicyHashing)?;
            let same_asset = Member::asset(&output.asset)
                .map_err(|_| TransferError::PolicyHashing)?
                .as_bytes()
                == asset;
            if same_asset
                && owner == *self.sender.as_bytes()
                && output.ring_program_id == Some(self.ring)
            {
                change = change
                    .checked_add(output.amount)
                    .ok_or(TransferError::VelocityOverflow)?;
            }
        }
        inflow
            .checked_sub(change)
            .ok_or(TransferError::VelocityOverflow)
    }
}

/// The rows charged for one transfer, shared by both velocity modes.
#[derive(Debug)]
pub(crate) struct RowCharges {
    pub rows: [VelocityRow; MAX_VELOCITY_ASSETS],
    pub row_count: u8,
    pub spent: [u64; MAX_VELOCITY_ASSETS],
    pub approval_required: bool,
}

/// Charges each row's outflow, `previous` supplied only inside a live window.
pub(crate) struct ChargeRows<'a> {
    pub rows: &'a [VelocityRow],
    pub outflows: &'a Outflows<'a>,
    pub previous: Option<&'a SpendCounters>,
}

impl ChargeRows<'_> {
    pub(crate) fn charge(self) -> Result<RowCharges, TransferError> {
        let mut charges = RowCharges {
            rows: [VelocityRow {
                asset: [0u8; 32],
                cap: 0,
                cosign_above: 0,
            }; MAX_VELOCITY_ASSETS],
            row_count: self.rows.len() as u8,
            spent: [0u64; MAX_VELOCITY_ASSETS],
            approval_required: false,
        };
        for (index, row) in self.rows.iter().enumerate() {
            charges.rows[index] = *row;
            let outflow = self.outflows.outflow(&row.asset)?;
            let previous = self
                .previous
                .map_or(0, |counters| counters.spent(&row.asset));
            let spent = previous
                .checked_add(outflow)
                .ok_or(TransferError::VelocityOverflow)?;
            if row.cap != 0 && spent > row.cap {
                return Err(TransferError::VelocityCapExceeded {
                    asset: row.asset,
                    cap: row.cap,
                    spent,
                });
            }
            charges.approval_required |= row.cosign_above != 0 && outflow > row.cosign_above;
            charges.spent[index] = spent;
        }
        Ok(charges)
    }
}

/// A field element below the modulus, the Poseidon commitment rejects the rest.
fn canonical_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt[0] = 0;
    salt
}

pub(crate) struct VelocityPlan {
    pub input: SppProofInputUtxo,
    pub output: SppProofOutputUtxo,
    /// The plaintext record slot `finalize` publishes at the output's position.
    pub record_slot: MessageData,
    pub counters_message: MessageData,
    pub witness: VelocityWitness,
    pub shape: Shape,
}

pub(crate) struct VelocityPlanInput<'a> {
    pub facts: &'a VelocityFacts,
    pub outflows: Outflows<'a>,
    pub tx_viewing_key: &'a ViewingKey,
    pub salt: [u8; 16],
    pub first_nullifier: [u8; 32],
    pub output_blinding_seed: [u8; 32],
    /// The money slots the record follows, dummies included.
    pub money_shape: Shape,
}

impl VelocityPlanInput<'_> {
    pub(crate) fn plan(self) -> Result<VelocityPlan, TransferError> {
        let facts = self.facts;
        let shape = record_shape(self.money_shape)?;
        let same_window = facts.live.record.window == facts.window_index;
        let previous = facts.counters.as_ref().filter(|_| same_window);
        let charges = ChargeRows {
            rows: &facts.rows,
            outflows: &self.outflows,
            previous,
        }
        .charge()?;
        let mut next = SpendCounters::zero(&[]);
        next.salt = canonical_salt();
        for index in 0..usize::from(charges.row_count) {
            next.assets[index] = charges.rows[index].asset;
            next.spent[index] = charges.spent[index];
        }
        let commitment = next
            .commitment()
            .map_err(|_| TransferError::PolicyHashing)?;
        let spent = &facts.live.record;
        let successor = SpendRecord {
            member: spent.member,
            version: spent
                .version
                .checked_add(1)
                .ok_or(TransferError::VelocityOverflow)?,
            window: facts.window_index,
            counters_commitment: commitment,
            blinding: derive_transact_output_blinding(
                &self.first_nullifier,
                &self.output_blinding_seed,
                shape.n_outputs() as u32 - 1,
            )?,
        };
        let address = facts
            .owner
            .spend_address(&spent.member, facts.entries_tree_id)
            .map_err(|_| TransferError::PolicyHashing)?;
        let spent_data_hash = spent
            .data_hash(&address)
            .map_err(|_| TransferError::PolicyHashing)?;
        let next_data_hash = successor
            .data_hash(&address)
            .map_err(|_| TransferError::PolicyHashing)?;
        let namespace_owner = PublicKey::from_pda(&facts.namespace);
        let zero_nullifier = NullifierKey::from_secret([0u8; 31]);
        let input = SppProofInputUtxo {
            utxo: Utxo {
                owner: namespace_owner,
                asset: SOL_MINT,
                amount: 0,
                blinding: spent.blinding,
                ring_program_id: None,
                data: Data::default(),
            },
            nullifier_key: zero_nullifier.clone(),
            data_hash: Some(spent_data_hash),
            ring_data_hash: None,
            tree_id: facts.entries_tree_id,
        };
        let output = SppProofOutputUtxo {
            asset: SOL_MINT,
            amount: 0,
            blinding: successor.blinding,
            ring_program_id: None,
            ring_data_hash: None,
            data_hash: Some(next_data_hash),
            owner_address: Some(ShieldedAddress::for_pda(
                &facts.namespace,
                zero_nullifier.pubkey()?,
                ViewingKey::new().pubkey(),
            )),
            owner_tag: Some(facts.namespace.to_bytes()),
            data: Data::default(),
        };
        let counters_body = encrypt_counters(
            self.tx_viewing_key,
            &self.tx_viewing_key.pubkey(),
            self.salt,
            &next,
        )?;
        let opened = facts.counters.unwrap_or_else(|| SpendCounters::zero(&[]));
        let witness = VelocityWitness {
            window_slots: facts.window_slots,
            rows: charges.rows,
            row_count: charges.row_count,
            ring_id: ring_id_field(self.outflows.ring.as_array())
                .map_err(|_| TransferError::PolicyHashing)?,
            namespace_owner_hash: facts.owner.owner_hash,
            window_index: facts.window_index,
            approval_required: charges.approval_required,
            record: SpendRecordWitness {
                version: spent.version,
                window: spent.window,
                commitment: spent.counters_commitment,
                salt: opened.salt,
                assets: opened.assets,
                spent: opened.spent,
                next_salt: next.salt,
            },
        };
        Ok(VelocityPlan {
            input,
            output,
            record_slot: MessageData {
                view_tag: facts.namespace.to_bytes(),
                data: successor.to_output_data().to_vec(),
            },
            counters_message: counters_message(facts.namespace.to_bytes(), counters_body),
            witness,
            shape,
        })
    }
}

/// The smallest supported shape with one slot beyond the money on each side.
pub(crate) fn record_shape(money: Shape) -> Result<Shape, TransferError> {
    let n_in = money.n_inputs() + 1;
    let n_out = money.n_outputs() + 1;
    zolana_client::SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| {
            shape.n_inputs() <= zolana_ring_policy::POLICY_INPUT_SLOTS
                && shape.n_outputs() <= zolana_ring_policy::POLICY_OUTPUT_SLOTS
        })
        .find(|shape| shape.n_inputs() >= n_in && shape.n_outputs() >= n_out)
        .ok_or(TransferError::PolicyShapeUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint() -> Address {
        Address::new_from_array([9u8; 32])
    }

    fn row_asset() -> [u8; 32] {
        *Member::asset(&mint()).expect("asset member").as_bytes()
    }

    fn money_input(amount: u64) -> SppProofInputUtxo {
        SppProofInputUtxo {
            utxo: Utxo {
                owner: PublicKey::from_pda(&Address::new_from_array([7u8; 32])),
                asset: mint(),
                amount,
                blinding: [0u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            nullifier_key: NullifierKey::from_secret([0u8; 31]),
            data_hash: None,
            ring_data_hash: None,
            tree_id: 0,
        }
    }

    fn charge(
        amount: u64,
        cap: u64,
        cosign_above: u64,
        previous: Option<u64>,
    ) -> Result<RowCharges, TransferError> {
        let inputs = [money_input(amount)];
        let outputs: [SppProofOutputUtxo; 0] = [];
        let outflows = Outflows {
            sender: Member::owner_tag(&[1u8; 32]).expect("sender"),
            ring: Address::default(),
            inputs: &inputs,
            outputs: &outputs,
        };
        let row = VelocityRow {
            asset: row_asset(),
            cap,
            cosign_above,
        };
        let counters = previous.map(|spent| {
            let mut counters = SpendCounters::zero(&[row_asset()]);
            counters.spent[0] = spent;
            counters
        });
        ChargeRows {
            rows: &[row],
            outflows: &outflows,
            previous: counters.as_ref(),
        }
        .charge()
    }

    #[test]
    fn the_record_takes_the_slot_after_the_money() {
        assert_eq!(record_shape(Shape::IN1_OUT1).unwrap(), Shape::IN2_OUT2);
        assert_eq!(record_shape(Shape::IN1_OUT2).unwrap(), Shape::IN2_OUT3);
        assert_eq!(record_shape(Shape::IN2_OUT3).unwrap(), Shape::IN4_OUT4);
        assert_eq!(record_shape(Shape::IN4_OUT3).unwrap(), Shape::IN5_OUT4);
        assert!(record_shape(Shape::IN4_OUT4).is_err());
    }

    #[test]
    fn a_transfer_under_the_cap_charges_its_outflow() {
        let charges = charge(100, 1000, 0, None).expect("under the cap");
        assert_eq!(charges.spent[0], 100);
        assert!(!charges.approval_required);
    }

    #[test]
    fn a_transfer_at_the_cap_passes() {
        let charges = charge(1000, 1000, 0, None).expect("at the cap");
        assert_eq!(charges.spent[0], 1000);
    }

    #[test]
    fn a_transfer_over_the_cap_is_refused_with_its_outflow() {
        let error = charge(1001, 1000, 0, None).expect_err("over the cap");
        assert!(matches!(
            error,
            TransferError::VelocityCapExceeded {
                asset,
                cap: 1000,
                spent: 1001,
            } if asset == row_asset()
        ));
    }

    #[test]
    fn the_threshold_reads_the_outflow_alone() {
        assert!(charge(600, 0, 500, None).expect("above").approval_required);
        assert!(!charge(500, 0, 500, None).expect("at").approval_required);
    }

    #[test]
    fn a_supplied_previous_adds_to_the_charge() {
        assert_eq!(charge(100, 0, 0, Some(50)).expect("windowed").spent[0], 150);
        assert_eq!(charge(100, 0, 0, None).expect("per transfer").spent[0], 100);
    }

    #[test]
    fn a_previous_over_the_cap_is_refused() {
        let error = charge(600, 1000, 0, Some(500)).expect_err("cumulative over the cap");
        assert!(matches!(
            error,
            TransferError::VelocityCapExceeded { spent: 1100, .. }
        ));
    }

    #[test]
    fn the_salt_stays_below_the_modulus() {
        for _ in 0..1000 {
            assert_eq!(canonical_salt()[0], 0);
        }
    }

    #[test]
    fn a_per_transfer_witness_carries_the_rows_and_no_record() {
        let charges = charge(100, 1000, 0, None).expect("charges");
        let witness = VelocityWitness::per_transfer(&charges, [1u8; 32], [2u8; 32]);
        assert_eq!(witness.window_slots, 0);
        assert_eq!(witness.window_index, 0);
        assert_eq!(witness.row_count, 1);
        assert_eq!(witness.record, SpendRecordWitness::default());
    }
}
