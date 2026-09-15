use futures::future::try_join;
use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    AsyncRpc, Proof, ProofCompressed, RingAuthorityProofResult, RingAuthorityProver, Rpc,
    SppProofInputUtxo, TransferInputs,
};
use zolana_interface::{
    instruction::{CircuitId, TransactIxData, TransactProof},
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{random_salt, ShieldedAddress, ViewingKey};
use zolana_transaction::{
    instructions::{
        ring_authority::{AuthoritySeal, PreparedRingAuthority, RingAuthorityMove},
        transact::SppProofOutputUtxo,
    },
    AssetRegistry,
};

use crate::{
    instructions::spend::ReadEnvironment,
    transfer::{
        frame_dummy_outputs, read_tree_state, read_tree_state_async, BoundTree, PolicyTierInput,
        RingInstructionData, RingMembership, RingSpendInputs, SpendSet, Tier, TierBinding,
        TierRequest, TierRequestInput,
    },
    AsyncTransferProofEnvironment, CustomRing, CustomRingDelegateTransact, CustomRingProof,
    CustomRingProofParams, EncryptedAudit, PendingCustomRingProof, TransferError,
    TransferProofEnvironment,
};

pub struct DelegateOutput {
    pub recipient: ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
}

pub struct DelegateTransferInput {
    pub ring: CustomRing,
    /// Signs the transaction beside the payer.
    pub delegate: Address,
    pub payer: Address,
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<DelegateOutput>,
}

#[must_use = "prove or discard the move explicitly"]
pub struct DelegateTransfer<'a> {
    ring: CustomRing,
    delegate: Address,
    payer: Address,
    inputs: Vec<SppProofInputUtxo>,
    outputs: Vec<DelegateOutput>,
    input_tree: Option<Address>,
    output_tree: Option<Address>,
    assets: Option<&'a AssetRegistry>,
    cosigner: Option<Address>,
}

#[must_use = "build or submit the proven move"]
pub struct ProvenDelegateTransfer {
    pub tx_viewing_key: ViewingKey,
    /// Padding included.
    pub outputs: Vec<SppProofOutputUtxo>,
    pub data: TransactIxData,
    pub proof: CustomRingProof,
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
    pub cosigner: Option<Address>,
    delegate: Address,
    payer: Address,
    input_tree: Address,
    output_tree: Address,
    entries_tree: Option<Address>,
    ring: CustomRing,
}

impl<'a> DelegateTransfer<'a> {
    pub fn new(input: DelegateTransferInput) -> Self {
        Self {
            ring: input.ring,
            delegate: input.delegate,
            payer: input.payer,
            inputs: input.inputs,
            outputs: input.outputs,
            input_tree: None,
            output_tree: None,
            assets: None,
            cosigner: None,
        }
    }

    pub fn with_tree(mut self, tree: Address) -> Self {
        self.input_tree = Some(tree);
        self
    }

    pub fn with_output_tree(mut self, tree: Address) -> Self {
        self.output_tree = Some(tree);
        self
    }

    pub fn with_assets(mut self, assets: &'a AssetRegistry) -> Self {
        self.assets = Some(assets);
        self
    }

    pub fn with_cosigner(mut self, cosigner: Address) -> Self {
        self.cosigner = Some(cosigner);
        self
    }

    pub fn prove<I: Rpc, R: Rpc>(
        self,
        env: TransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenDelegateTransfer, TransferError> {
        let config = self
            .ring
            .read_config(env.rpc)?
            .ok_or(TransferError::MissingRingConfig)?;
        let stored = self
            .ring
            .read_delegate(env.rpc)?
            .ok_or(TransferError::MissingDelegate)?;
        if stored.delegate != self.delegate {
            return Err(TransferError::UnauthorizedDelegate(stored.delegate));
        }
        let input_tree = self.input_tree.ok_or(TransferError::TreeRequired)?;
        let output_tree = self.output_tree.unwrap_or(input_tree);
        let input_state = read_tree_state(env.rpc, input_tree)?;
        let output_state = read_tree_state(env.rpc, output_tree)?;
        let staged = self.stage(
            config.auditor_pubkey,
            DelegateTrees {
                input: input_state.tree,
                output: output_state.tree,
            },
        )?;
        let spends = SpendSet {
            inputs: RingSpendInputs {
                indexer: env.indexer,
                tree: input_tree,
                spends: &staged.prepared.inputs,
            }
            .load()?,
            allow_dummy_inputs: input_state.allow_dummy_inputs,
        };
        let tier = if config.has_policy {
            staged.policy_tier().read(ReadEnvironment {
                indexer: env.indexer,
                rpc: env.rpc,
            })?
        } else {
            Tier::Base
        };
        let witnessed = staged.witness(spends, tier)?;
        let spp_proof =
            ProofCompressed::try_from(env.prover.prove_ring_authority(witnessed.spp())?)?
                .to_transact_proof();
        let ring_proof = env.prover.prove(&witnessed.request)?;
        witnessed.finish(spp_proof, ring_proof)
    }

    /// The async twin of [`Self::prove`].
    pub async fn prove_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: AsyncTransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenDelegateTransfer, TransferError> {
        let config = self
            .ring
            .read_config_async(env.rpc)
            .await?
            .ok_or(TransferError::MissingRingConfig)?;
        let stored = self
            .ring
            .read_delegate_async(env.rpc)
            .await?
            .ok_or(TransferError::MissingDelegate)?;
        if stored.delegate != self.delegate {
            return Err(TransferError::UnauthorizedDelegate(stored.delegate));
        }
        let input_tree = self.input_tree.ok_or(TransferError::TreeRequired)?;
        let output_tree = self.output_tree.unwrap_or(input_tree);
        let input_state = read_tree_state_async(env.rpc, input_tree).await?;
        let output_state = read_tree_state_async(env.rpc, output_tree).await?;
        let staged = self.stage(
            config.auditor_pubkey,
            DelegateTrees {
                input: input_state.tree,
                output: output_state.tree,
            },
        )?;
        let spends = SpendSet {
            inputs: RingSpendInputs {
                indexer: env.indexer,
                tree: input_tree,
                spends: &staged.prepared.inputs,
            }
            .load_async()
            .await?,
            allow_dummy_inputs: input_state.allow_dummy_inputs,
        };
        let tier = if config.has_policy {
            staged
                .policy_tier()
                .read_async(ReadEnvironment {
                    indexer: env.indexer,
                    rpc: env.rpc,
                })
                .await?
        } else {
            Tier::Base
        };
        let witnessed = staged.witness(spends, tier)?;
        let (spp, ring) = try_join(
            env.prover.prove_ring_authority(witnessed.spp()),
            env.prover.prove(&witnessed.request),
        )
        .await?;
        witnessed.finish(ProofCompressed::try_from(spp)?.to_transact_proof(), ring)
    }

    /// The auditor message joins `external_data` ahead of every hash over it.
    fn stage(
        self,
        auditor_pk: zolana_keypair::P256Pubkey,
        trees: DelegateTrees,
    ) -> Result<StagedDelegateTransfer, TransferError> {
        let assets = self.assets.ok_or(TransferError::MissingAssetRegistry)?;
        let program_id = self.ring.program_id();
        if let Some(input) = self
            .inputs
            .iter()
            .find(|input| !input.is_dummy() && input.tree_id != trees.input.id)
        {
            return Err(TransferError::TreeIdMismatch {
                tree: trees.input.address,
                expected: trees.input.id,
                found: input.tree_id,
            });
        }
        let outputs = self
            .outputs
            .into_iter()
            .map(|output| {
                Ok(SppProofOutputUtxo {
                    owner_tag: Some(output.recipient.signing_pubkey.confidential_view_tag()?),
                    owner_address: Some(output.recipient),
                    asset: output.asset,
                    amount: output.amount,
                    ring_program_id: Some(program_id),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, TransferError>>()?;
        RingMembership {
            program_id,
            inputs: &self.inputs,
            outputs: &outputs,
        }
        .validate()?;
        check_balance(&self.inputs, &outputs)?;
        let tx_viewing_key = ViewingKey::new();
        let EncryptedAudit {
            pending: pending_proof,
            message: auditor_message,
        } = CustomRingProofParams {
            tx_viewing_key: tx_viewing_key.clone(),
            auditor_pk,
        }
        .encrypt()?;
        let mut prepared = RingAuthorityMove {
            ring_program_id: program_id,
            inputs: self.inputs,
            outputs,
            payer: self.payer,
            input_tree_id: trees.input.id,
            output_tree_id: trees.output.id,
        }
        .prepare()?
        .finalize(AuthoritySeal {
            tx: &tx_viewing_key,
            assets,
            salt: random_salt(),
        })?;
        frame_dummy_outputs(&prepared.outputs, &mut prepared.external_data.outputs)?;
        prepared.external_data.messages = vec![auditor_message.to_message_data(&auditor_pk)];
        Ok(StagedDelegateTransfer {
            tx_viewing_key,
            pending_proof,
            prepared,
            delegate: self.delegate,
            input_tree: trees.input.address,
            output_tree: trees.output.address,
            ring: self.ring,
            cosigner: self.cosigner,
        })
    }
}

struct DelegateTrees {
    input: BoundTree,
    output: BoundTree,
}

/// Every asset moved in equals the asset moved out.
fn check_balance(
    inputs: &[SppProofInputUtxo],
    outputs: &[SppProofOutputUtxo],
) -> Result<(), TransferError> {
    let mut assets: Vec<Address> = inputs
        .iter()
        .filter(|input| !input.is_dummy())
        .map(|input| input.utxo.asset)
        .chain(outputs.iter().map(|output| output.asset))
        .collect();
    assets.sort_unstable();
    assets.dedup();
    for asset in assets {
        let moved_in: u128 = inputs
            .iter()
            .filter(|input| !input.is_dummy() && input.utxo.asset == asset)
            .map(|input| u128::from(input.utxo.amount))
            .sum();
        let moved_out: u128 = outputs
            .iter()
            .filter(|output| output.asset == asset)
            .map(|output| u128::from(output.amount))
            .sum();
        if moved_in != moved_out {
            return Err(TransferError::UnbalancedMove(asset));
        }
    }
    Ok(())
}

struct StagedDelegateTransfer {
    tx_viewing_key: ViewingKey,
    pending_proof: PendingCustomRingProof,
    prepared: PreparedRingAuthority,
    delegate: Address,
    input_tree: Address,
    output_tree: Address,
    ring: CustomRing,
    cosigner: Option<Address>,
}

impl StagedDelegateTransfer {
    fn policy_tier(&self) -> PolicyTierInput<'_> {
        PolicyTierInput {
            ring: self.ring,
            inputs: &self.prepared.inputs,
            outputs: &self.prepared.outputs,
            output_tree_id: self.prepared.output_tree_id,
            velocity: None,
        }
    }

    fn witness(
        self,
        spends: SpendSet,
        tier: Tier,
    ) -> Result<WitnessedDelegateTransfer, TransferError> {
        let shape = self.prepared.shape;
        let result = RingAuthorityProver {
            inputs: spends.inputs,
            outputs: self.prepared.outputs.clone(),
            blinding_seed: self.prepared.blinding_seed,
            output_tree_id: self.prepared.output_tree_id,
            external_data: self.prepared.external_data.clone(),
            public_transfers: self.prepared.public_transfers,
            payer: self.prepared.payer,
            allow_dummy_inputs: spends.allow_dummy_inputs,
            ring_program_id: self.prepared.ring_program_id,
            shape: Some(shape),
        }
        .build()?;
        let request = TierRequestInput {
            tier,
            pending: self.pending_proof,
            private_tx_hash: result.private_tx_hash.try_into()?,
            external_data: &self.prepared.external_data,
            private_tx_blinding: self.prepared.private_tx_blinding()?,
        }
        .build()?
        .for_delegate();
        Ok(WitnessedDelegateTransfer {
            request,
            tx_viewing_key: self.tx_viewing_key,
            prepared: self.prepared,
            result,
            delegate: self.delegate,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            ring: self.ring,
            cosigner: self.cosigner,
        })
    }
}

struct WitnessedDelegateTransfer {
    request: TierRequest,
    tx_viewing_key: ViewingKey,
    prepared: PreparedRingAuthority,
    result: RingAuthorityProofResult,
    delegate: Address,
    input_tree: Address,
    output_tree: Address,
    ring: CustomRing,
    cosigner: Option<Address>,
}

impl WitnessedDelegateTransfer {
    fn spp(&self) -> &TransferInputs {
        &self.result.inputs
    }

    fn finish(
        self,
        spp_proof: TransactProof,
        ring_proof: Proof,
    ) -> Result<ProvenDelegateTransfer, TransferError> {
        let TierBinding {
            proof,
            entries_tree,
            state_root_index,
            nullifier_root_index,
            approval_required: _,
            head_transition: _,
        } = self.request.proven(ring_proof)?.binding();
        let width = self.prepared.shape.n_inputs() as u8;
        Ok(ProvenDelegateTransfer {
            tx_viewing_key: self.tx_viewing_key,
            outputs: self.prepared.outputs.clone(),
            data: RingInstructionData {
                external_data: &self.prepared.external_data,
                nullifiers: &self.result.nullifiers,
                input_tree_indexes: &self.result.input_tree_indexes,
                tree_contexts: &self.result.tree_contexts,
                private_tx_hash: self.result.private_tx_hash,
                proof: spp_proof,
                circuit: CircuitId::RingAuthority(width, width, N_PUBLIC_SLOTS as u8),
            }
            .assemble()?,
            proof,
            state_root_index,
            nullifier_root_index,
            cosigner: self.cosigner,
            delegate: self.delegate,
            payer: self.prepared.payer,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            entries_tree,
            ring: self.ring,
        })
    }
}

impl ProvenDelegateTransfer {
    pub fn instruction(&self) -> Result<Instruction, TransferError> {
        CustomRingDelegateTransact {
            ring: self.ring,
            payer: self.payer,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            entries_tree: self.entries_tree,
            cosigner: self.cosigner,
            delegate: self.delegate,
            proof: self.proof,
            transact: self.data.clone(),
            state_root_index: self.state_root_index,
            nullifier_root_index: self.nullifier_root_index,
        }
        .instruction()
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use zolana_interface::{
        event::OutputDataEncoding,
        instruction::instruction_data::transact::ring_confidential_encrypted_output_body,
    };
    use zolana_keypair::{random_blinding, random_salt, ShieldedKeypair};
    use zolana_transaction::{Data, Utxo, SOL_MINT};

    use super::*;

    const RING: Address = Address::new_from_array([42u8; 32]);

    fn note(owner: &ShieldedKeypair, amount: u64) -> SppProofInputUtxo {
        SppProofInputUtxo::new(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: SOL_MINT,
                amount,
                blinding: random_blinding(),
                ring_program_id: Some(RING),
                data: Data::default(),
            },
            owner,
        )
        .in_tree(0)
    }

    fn recipient(owner: &ShieldedKeypair, amount: u64) -> SppProofOutputUtxo {
        SppProofOutputUtxo {
            ring_program_id: Some(RING),
            ..SppProofOutputUtxo::new(SOL_MINT, amount, owner.shielded_address().expect("address"))
                .expect("output")
        }
    }

    /// The ring program admits only framed confidential slots, a padded move
    /// carries them.
    #[test]
    fn padded_outputs_are_framed_like_real_slots() {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        let mut prepared = RingAuthorityMove {
            ring_program_id: RING,
            inputs: vec![note(&member, 5), note(&member, 7)],
            outputs: vec![recipient(&member, 12)],
            payer: Address::new_from_array([9u8; 32]),
            input_tree_id: 0,
            output_tree_id: 0,
        }
        .prepare()
        .expect("drafted")
        .finalize(AuthoritySeal {
            tx: &ViewingKey::new(),
            assets: &AssetRegistry::default(),
            salt: random_salt(),
        })
        .expect("prepared");
        frame_dummy_outputs(&prepared.outputs, &mut prepared.external_data.outputs)
            .expect("framed");
        for output in &prepared.external_data.outputs {
            let data = output.data.as_deref().expect("published slot");
            let OutputDataEncoding::Encrypted(_) =
                borsh::from_slice::<OutputDataEncoding>(data).expect("framed encoding")
            else {
                panic!("a padded slot must publish as encrypted");
            };
            let body = ring_confidential_encrypted_output_body(data).expect("ring scheme");
            assert!(matches!(body.first(), Some(2 | 3)));
        }
    }

    #[test]
    fn an_unbalanced_move_is_refused_before_proving() {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        let outputs = vec![recipient(&member, 4)];
        assert!(matches!(
            check_balance(&[note(&member, 5)], &outputs),
            Err(TransferError::UnbalancedMove(asset)) if asset == SOL_MINT
        ));
        check_balance(&[note(&member, 4)], &outputs).expect("balanced");
    }
}
