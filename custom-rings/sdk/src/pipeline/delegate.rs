use solana_address::Address;
use zolana_client::{AsyncRpc, ProofInputUtxo};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{OwnerTag, TransactOutput},
        tag::RING_AUTHORITY_TRANSACT,
    },
    shape::RING_AUTHORITY_WIDTHS,
};
use zolana_keypair::{random_blinding, random_salt, NullifierKey, ShieldedAddress, ViewingKey};
use zolana_transaction::{
    instructions::transact::{SppProofInputs, SppProofOutputUtxo},
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    AssetRegistry, ExternalData, Mint, TransactionError,
};

use super::{
    frame_dummy_outputs, owner::check_membership, sealed, Rail, RailKind, RingTransfer, Staged,
    TransferAuthority,
};
use crate::{
    escrow::KeyRegistry, CustomRing, CustomRingConfig, CustomRingProofParams, EncryptedAudit,
    RingError,
};

#[derive(Clone)]
pub struct DelegateOutput {
    pub recipient: ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
}

/// The delegate moves a member's notes with the recovered key, the member does not sign.
pub struct Delegated<'a> {
    delegate: Address,
    payer: Address,
    source: NullifierKey,
    inputs: Vec<SppProofInputUtxo>,
    outputs: Vec<DelegateOutput>,
    output_tree_id: Option<u16>,
    assets: Option<&'a AssetRegistry>,
}

pub struct DelegateTransferInput<'a> {
    pub ring: CustomRing,
    /// Signs the transaction beside the payer.
    pub delegate: Address,
    pub payer: Address,
    /// The recovered key of the source member completes the ownership witnesses.
    pub source_nullifier_key: &'a NullifierKey,
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<DelegateOutput>,
}

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
                source: input.source_nullifier_key.clone(),
                inputs: input.inputs,
                outputs: input.outputs,
                output_tree_id: None,
                assets: None,
            },
            cosigner: None,
            indexer_config: None,
        }
    }

    /// The outputs land in the first input's tree unless moved here.
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
}

/// The smallest square ring authority circuit with at least `slots` inputs and outputs.
pub fn ring_authority_width(slots: usize) -> Option<usize> {
    RING_AUTHORITY_WIDTHS
        .into_iter()
        .find(|&width| width >= slots)
}

impl Delegated<'_> {
    /// The auditor message joins the external data ahead of every hash over it.
    pub(super) async fn stage(
        &self,
        ring: CustomRing,
        client: &(impl AsyncRpc + ?Sized),
        config: &CustomRingConfig,
    ) -> Result<Staged, RingError> {
        let stored = ring
            .delegate(client)
            .await?
            .ok_or(RingError::MissingDelegate)?;
        if stored != self.delegate {
            return Err(RingError::UnauthorizedDelegate(stored));
        }
        let key_registry =
            KeyRegistry::of(ring, config).ok_or(RingError::DelegateRequiresEscrow)?;
        let pinned = ring
            .pinned_policy(client)
            .await?
            .ok_or(RingError::MissingPolicyConfig)?;
        let assets = self.assets.ok_or(RingError::MissingAssetRegistry)?;
        let program = ring.program_id();
        let first = self.inputs.first().ok_or(TransactionError::NoInputs)?;
        let output_tree_id = self.output_tree_id.unwrap_or(first.tree_id);
        let mut outputs = self
            .outputs
            .iter()
            .map(|output| {
                Ok(SppProofOutputUtxo {
                    owner_tag: Some(output.recipient.signing_pubkey.confidential_view_tag()?),
                    owner_address: Some(output.recipient),
                    asset: assets.mint(&output.asset)?,
                    amount: output.amount,
                    ring_program_id: Some(program),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        check_membership(program, &self.inputs, &outputs)?;
        check_balance(&self.inputs, &outputs)?;
        let mut inputs = self.inputs.clone();
        pad(&mut inputs, &mut outputs, program)?;
        let tx_viewing_key = ViewingKey::new();
        let salt = random_salt();
        let blinding_seed = random_blinding();
        let first_nullifier = inputs[0].nullifier();
        let output_seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed)?;
        let mut external_outputs = Vec::with_capacity(outputs.len());
        let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
        let dummy_tag = outputs[0].owner_tag.unwrap_or_default();
        for (slot, output) in outputs.iter_mut().enumerate() {
            let slot = u32::try_from(slot).map_err(|_| TransactionError::TooManyOutputs)?;
            output.blinding =
                derive_transact_output_blinding(&first_nullifier, &output_seed, slot)?;
            let (tag, data) = match output.owner_address {
                Some(_) => {
                    let sealed = output.seal(slot, &tx_viewing_key, salt)?;
                    (sealed.view_tag, Some(sealed.data))
                }
                None => (dummy_tag, None),
            };
            external_outputs.push(TransactOutput {
                utxo_hash: output.hash(output_tree_id)?,
                owner_tag: OwnerTag::Inline(tag),
                data,
            });
            resolved_owner_tags.push(tag);
        }
        let EncryptedAudit { pending, message } = CustomRingProofParams {
            tx_viewing_key: tx_viewing_key.clone(),
            auditor_pk: config.auditor_pubkey,
            salt,
            outputs: outputs
                .iter()
                .map(|output| ProofInputUtxo::try_from((output, output_tree_id)))
                .collect::<Result<_, _>>()?,
        }
        .encrypt()?;
        frame_dummy_outputs(&outputs, &mut external_outputs)?;
        let mut external_data = ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            salt,
            external_outputs,
            resolved_owner_tags,
            vec![message.to_message_data(&config.auditor_pubkey)],
        );
        external_data.instruction_discriminator = RING_AUTHORITY_TRANSACT;
        Ok(Staged {
            proof_inputs: SppProofInputs {
                input_utxos: inputs,
                output_utxos: outputs,
                blinding_seed,
                output_tree_id,
                external_data,
                payer: self.payer,
                cache_accounts: Default::default(),
            },
            pending,
            tx_viewing_key,
            pinned: Some(pinned),
            velocity: None,
            record: None,
            authority: TransferAuthority {
                owner: Some(self.source.clone()),
                spend_record: None,
            },
            key_registry: Some(key_registry),
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            delegate: Some(self.delegate),
        })
    }
}

/// Pads to the smallest square width, dummy outputs name a recipient and the ring,
/// dummy inputs sit under the last declared tree.
fn pad(
    inputs: &mut Vec<SppProofInputUtxo>,
    outputs: &mut Vec<SppProofOutputUtxo>,
    program: Address,
) -> Result<(), RingError> {
    if inputs.first().is_none_or(SppProofInputUtxo::is_dummy) {
        return Err(TransactionError::NoInputs.into());
    }
    if outputs.is_empty() || outputs.iter().any(SppProofOutputUtxo::is_dummy) {
        return Err(TransactionError::MissingOutput.into());
    }
    let width = ring_authority_width(inputs.len().max(outputs.len())).ok_or(
        TransactionError::UnsupportedShape {
            n_in: inputs.len(),
            n_out: outputs.len(),
        },
    )?;
    let dummy_tag = outputs[0].owner_tag;
    outputs.resize_with(width, || SppProofOutputUtxo {
        owner_tag: dummy_tag,
        ring_program_id: Some(program),
        ..Default::default()
    });
    let mut padding_tree = inputs[0].tree_id;
    for (index, input) in inputs.iter().enumerate() {
        if !input.is_dummy()
            && inputs[..index]
                .iter()
                .all(|earlier| earlier.tree_id != input.tree_id)
        {
            padding_tree = input.tree_id;
        }
    }
    while inputs.len() < width {
        inputs.push(SppProofInputUtxo::dummy(padding_tree)?);
    }
    if let Some((index, input)) = inputs
        .iter()
        .enumerate()
        .find(|(_, input)| input.is_dummy() && input.tree_id != padding_tree)
    {
        return Err(TransactionError::PaddingInUndeclaredTree {
            index,
            tree_id: input.tree_id,
        }
        .into());
    }
    Ok(())
}

/// Every asset moved in equals the asset moved out.
fn check_balance(
    inputs: &[SppProofInputUtxo],
    outputs: &[SppProofOutputUtxo],
) -> Result<(), RingError> {
    let real = inputs.iter().filter(|input| !input.is_dummy());
    let moved = real
        .clone()
        .map(|input| (input.utxo.asset, i128::from(input.utxo.amount)))
        .chain(
            outputs
                .iter()
                .map(|output| (output.asset, -i128::from(output.amount))),
        );
    let mut balances: Vec<(Mint, i128)> = Vec::new();
    for (asset, amount) in moved {
        match balances.iter_mut().find(|(known, _)| *known == asset) {
            Some((_, balance)) => *balance += amount,
            None => balances.push((asset, amount)),
        }
    }
    match balances.into_iter().find(|(_, balance)| *balance != 0) {
        Some((asset, _)) => Err(RingError::UnbalancedMove(asset.asset)),
        None => Ok(()),
    }
}
