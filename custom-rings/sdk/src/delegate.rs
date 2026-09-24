use crate::{
    authority::{AuthoritySeal, RingAuthorityMove},
    RingAuthorityProofInputs,
};
use futures::future::try_join;
use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    AsyncRpc, Proof, ProofAuthority, ProofCompressed, ProofInputUtxo, Prover,
    RingAuthorityProofResult, RingAuthorityProver, Rpc, TransferInputs,
};
use zolana_interface::{
    instruction::{CircuitId, TransactIxData, TransactProof},
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{random_salt, NullifierKey, ShieldedAddress, ViewingKey};
use zolana_transaction::{
    instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo, AssetRegistry,
};

use crate::{
    escrow::KeyRegistry,
    instructions::{spend::ReadEnvironment, transact::PolicyReads},
    transfer::{
        frame_dummy_outputs, PolicyBinding, PolicyRequest, PolicyStatement, PolicyTierInput,
        RingInstructionData, RingMembership, RingSpendInputs, SpendSet, SpendTreePlan, SpendTrees,
        TierRequestInput,
    },
    AsyncTransferProofEnvironment, CustomRing, CustomRingDelegateTransact, CustomRingProof,
    CustomRingProofParams, EncryptedAudit, PendingCustomRingProof, PoolTree, TransferError,
    TransferProofEnvironment,
};

#[derive(Clone)]
pub struct DelegateOutput {
    pub recipient: ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
}

pub struct DelegateTransferInput<'a> {
    pub ring: CustomRing,
    /// Signs the transaction beside the payer.
    pub delegate: Address,
    pub payer: Address,
    /// The recovered source member key completes ownership witnesses without
    /// making the member sign the delegated transaction.
    pub source_nullifier_key: &'a NullifierKey,
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<DelegateOutput>,
}

#[must_use = "prove or discard the move explicitly"]
#[derive(Clone)]
pub struct DelegateTransfer<'a> {
    ring: CustomRing,
    delegate: Address,
    payer: Address,
    source_nullifier_key: NullifierKey,
    inputs: Vec<SppProofInputUtxo>,
    outputs: Vec<DelegateOutput>,
    output_tree_id: Option<u16>,
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
    pub policy: PolicyReads,
    pub cosigner: Option<Address>,
    delegate: Address,
    payer: Address,
    trees: SpendTrees,
    ring: CustomRing,
}

impl<'a> DelegateTransfer<'a> {
    pub fn new(input: DelegateTransferInput<'a>) -> Self {
        Self {
            ring: input.ring,
            delegate: input.delegate,
            payer: input.payer,
            source_nullifier_key: input.source_nullifier_key.clone(),
            inputs: input.inputs,
            outputs: input.outputs,
            output_tree_id: None,
            assets: None,
            cosigner: None,
        }
    }

    /// The outputs land in the first input's tree unless moved here.
    #[must_use = "use the updated move"]
    pub fn with_output_tree_id(mut self, tree_id: u16) -> Self {
        self.output_tree_id = Some(tree_id);
        self
    }

    #[must_use = "use the updated move"]
    pub fn with_assets(mut self, assets: &'a AssetRegistry) -> Self {
        self.assets = Some(assets);
        self
    }

    #[must_use = "use the updated move"]
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
        let key_registry =
            KeyRegistry::of(self.ring, &config).ok_or(TransferError::DelegateRequiresEscrow)?;
        let staged = self.stage(config.auditor_pubkey, key_registry)?;
        let spends = SpendSet {
            trees: staged.tree_plan().read(env.rpc)?,
            inputs: RingSpendInputs {
                indexer: env.indexer,
                input_utxos: &staged.prepared.inputs,
            }
            .load()?,
        };
        let statement = staged.policy_tier().read(ReadEnvironment {
            indexer: env.indexer,
            rpc: env.rpc,
        })?;
        let witnessed = staged.witness(spends, statement)?;
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
        let key_registry =
            KeyRegistry::of(self.ring, &config).ok_or(TransferError::DelegateRequiresEscrow)?;
        let staged = self.stage(config.auditor_pubkey, key_registry)?;
        let spends = SpendSet {
            trees: staged.tree_plan().read_async(env.rpc).await?,
            inputs: RingSpendInputs {
                indexer: env.indexer,
                input_utxos: &staged.prepared.inputs,
            }
            .load_async()
            .await?,
        };
        let statement = staged
            .policy_tier()
            .read_async(ReadEnvironment {
                indexer: env.indexer,
                rpc: env.rpc,
            })
            .await?;
        let witnessed = staged.witness(spends, statement)?;
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
        key_registry: KeyRegistry,
    ) -> Result<StagedDelegateTransfer, TransferError> {
        let assets = self.assets.ok_or(TransferError::MissingAssetRegistry)?;
        let output_tree = self
            .output_tree_id
            .or_else(|| self.inputs.first().map(|input| input.tree_id))
            .map(PoolTree::from_id)
            .ok_or(zolana_transaction::TransactionError::NoInputs)?;
        let program_id = self.ring.program_id();
        // Padding joins the last input group, SPP requires contiguous groups.
        let padding_tree_id = self
            .inputs
            .last()
            .map(|input| input.tree_id)
            .ok_or(zolana_transaction::TransactionError::NoInputs)?;
        let outputs = self
            .outputs
            .into_iter()
            .map(|output| {
                Ok(SppProofOutputUtxo {
                    owner_tag: Some(output.recipient.signing_pubkey.confidential_view_tag()?),
                    owner_address: Some(output.recipient),
                    asset: assets.mint(&output.asset)?,
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
        let salt = random_salt();
        let mut prepared = RingAuthorityMove {
            ring_program_id: program_id,
            inputs: self.inputs,
            outputs,
            payer: self.payer,
            input_tree_id: padding_tree_id,
            output_tree_id: output_tree.id,
        }
        .prepare()?
        .finalize(AuthoritySeal {
            tx: &tx_viewing_key,
            assets,
            salt,
        })?;
        let EncryptedAudit {
            pending: pending_proof,
            message: auditor_message,
        } = CustomRingProofParams {
            tx_viewing_key: tx_viewing_key.clone(),
            auditor_pk,
            salt,
            outputs: prepared
                .outputs
                .iter()
                .map(|output| ProofInputUtxo::try_from((output, output_tree.id)))
                .collect::<Result<Vec<_>, _>>()?,
        }
        .encrypt()?;
        frame_dummy_outputs(&prepared.outputs, &mut prepared.external_data.outputs)?;
        prepared.external_data.messages = vec![auditor_message.to_message_data(&auditor_pk)];
        Ok(StagedDelegateTransfer {
            tx_viewing_key,
            pending_proof,
            prepared,
            source_nullifier_key: self.source_nullifier_key,
            delegate: self.delegate,
            output_tree,
            key_registry,
            ring: self.ring,
            cosigner: self.cosigner,
        })
    }
}

/// Every asset moved in equals the asset moved out.
fn check_balance(
    inputs: &[SppProofInputUtxo],
    outputs: &[SppProofOutputUtxo],
) -> Result<(), TransferError> {
    let mut assets: Vec<_> = inputs
        .iter()
        .filter(|input| !input.is_dummy())
        .map(|input| input.utxo.asset)
        .chain(outputs.iter().map(|output| output.asset))
        .collect();
    let mut unique = Vec::with_capacity(assets.len());
    for asset in assets.drain(..) {
        if !unique.contains(&asset) {
            unique.push(asset);
        }
    }
    for asset in unique {
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
            return Err(TransferError::UnbalancedMove(asset.asset));
        }
    }
    Ok(())
}

struct StagedDelegateTransfer {
    tx_viewing_key: ViewingKey,
    pending_proof: PendingCustomRingProof,
    prepared: RingAuthorityProofInputs,
    source_nullifier_key: NullifierKey,
    delegate: Address,
    output_tree: PoolTree,
    key_registry: KeyRegistry,
    ring: CustomRing,
    cosigner: Option<Address>,
}

impl StagedDelegateTransfer {
    fn tree_plan(&self) -> SpendTreePlan {
        SpendTreePlan::new(&self.prepared.inputs, self.output_tree)
    }

    fn policy_tier(&self) -> PolicyTierInput<'_> {
        PolicyTierInput {
            ring: self.ring,
            inputs: &self.prepared.inputs,
            outputs: &self.prepared.outputs,
            output_tree_id: self.prepared.output_tree_id,
            velocity: None,
            key_registry: Some(self.key_registry),
        }
    }

    fn witness(
        self,
        spends: SpendSet,
        statement: PolicyStatement,
    ) -> Result<WitnessedDelegateTransfer, TransferError> {
        let SpendSet { inputs, trees } = spends;
        let shape = self.prepared.shape;
        let mut result = RingAuthorityProver {
            inputs,
            outputs: self.prepared.outputs.clone(),
            blinding_seed: self.prepared.blinding_seed,
            output_tree_id: self.prepared.output_tree_id,
            external_data: self.prepared.external_data.clone(),
            public_transfers: self.prepared.public_transfers,
            payer: self.prepared.payer,
            allow_dummy_inputs: trees.allow_dummy_inputs,
            ring_program_id: self.prepared.ring_program_id,
            shape,
        }
        .build()?;
        self.source_nullifier_key
            .complete_inputs(&mut result.inputs.inputs)?;
        let request = TierRequestInput {
            pending: self.pending_proof,
            private_tx_hash: result.private_tx_hash.try_into()?,
            external_data: &self.prepared.external_data,
            private_tx_blinding: self.prepared.private_tx_blinding()?,
        }
        .policy(statement)?
        .for_delegate();
        Ok(WitnessedDelegateTransfer {
            request,
            tx_viewing_key: self.tx_viewing_key,
            prepared: self.prepared,
            result,
            delegate: self.delegate,
            trees,
            ring: self.ring,
            cosigner: self.cosigner,
        })
    }
}

struct WitnessedDelegateTransfer {
    request: PolicyRequest,
    tx_viewing_key: ViewingKey,
    prepared: RingAuthorityProofInputs,
    result: RingAuthorityProofResult,
    delegate: Address,
    trees: SpendTrees,
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
        let PolicyBinding {
            proof,
            reads: policy,
            approval_required: _,
        } = self.request.proven(ring_proof)?;
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
            policy,
            cosigner: self.cosigner,
            delegate: self.delegate,
            payer: self.prepared.payer,
            trees: self.trees,
            ring: self.ring,
        })
    }
}

impl ProvenDelegateTransfer {
    pub fn instruction(&self) -> Result<Instruction, TransferError> {
        CustomRingDelegateTransact {
            ring: self.ring,
            payer: self.payer,
            input_trees: self.trees.inputs.clone(),
            output_tree: self.trees.output,
            policy: self.policy.clone(),
            cosigner: self.cosigner,
            delegate: self.delegate,
            proof: self.proof,
            transact: self.data.clone(),
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
    use zolana_transaction::{Data, Mint, Utxo};

    use super::*;

    const RING: Address = Address::new_from_array([42u8; 32]);

    fn note(owner: &ShieldedKeypair, amount: u64) -> SppProofInputUtxo {
        zolana_test_utils::utxo::wallet(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: Mint::SOL,
                amount,
                blinding: random_blinding(),
                ring_program_id: Some(RING),
                data: Data::default(),
            },
            &owner.nullifier_key,
            0,
            0,
            None,
            None,
        )
        .expect("wallet UTXO")
        .into()
    }

    fn recipient(owner: &ShieldedKeypair, amount: u64) -> SppProofOutputUtxo {
        SppProofOutputUtxo {
            ring_program_id: Some(RING),
            ..SppProofOutputUtxo::new(
                Mint::SOL,
                amount,
                owner.shielded_address().expect("address"),
            )
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
            Err(TransferError::UnbalancedMove(asset)) if asset == Mint::SOL.asset
        ));
        check_balance(&[note(&member, 4)], &outputs).expect("balanced");
    }
}
