use solana_address::Address;
use zolana_event::MessageData;
use zolana_interface::{
    instruction::instruction_data::transact::{OwnerTag, TransactOutput},
    shape::Shape,
};
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN},
    hash::sha256_be,
    random_salt,
    shielded::ShieldedAddress,
    viewing_key::random_blinding,
    P256Pubkey, ShieldedKeypairTrait, SignatureType, ViewingKeyTrait,
};

use super::{
    spp_proof_inputs::SppProofInputs, transfer::random_view_tag, ExternalData, SppProofOutputUtxo,
};
use crate::{
    data::Data,
    error::TransactionError,
    instructions::{merge::has_data, types::SppProofInputUtxo},
    serialization::{
        split::{Split, SplitBundlePlaintext, SplitEncode},
        UtxoSerialization,
    },
    utxo::derive_blinding,
    AssetRegistry,
};

/// A split is a 1-input -> N-output self-transfer of a single asset into N
/// equal utxos (`N` in `2..=8`). It always fills the `IN1_OUT8` shape: the `N`
/// real self-owned outputs occupy slots `0..N`, and `8 - N` zero-value dummies
/// pad the tail so the padded balance still sums to the input. All `N` real
/// outputs are encoded in a single `Split` bundle ciphertext published at slot
/// 0; the remaining real slots and every dummy slot carry no ciphertext of
/// their own (`data == None`), so the bundle at slot 0 covers them.
pub struct ConfidentialSplit {
    pub owner: ShieldedAddress,
    pub input: SppProofInputUtxo,
    pub asset: Address,
    pub num_outputs: u8,
    pub per_output_amount: u64,
    pub payer_pubkey_hash: [u8; 32],
    pub blinding_seed: [u8; BLINDING_LEN],
}

const MIN_PARTS: u8 = 2;

impl ConfidentialSplit {
    /// Validate the split shape and input before assembly: `num_outputs` in
    /// `2..=8`, the input matches `asset`, the input is a plain utxo (no zone
    /// binding and no attached data), and `num_outputs * per_output_amount`
    /// equals the input amount so the circuit balance holds.
    pub fn new(
        owner: ShieldedAddress,
        input: SppProofInputUtxo,
        asset: Address,
        num_outputs: u8,
        per_output_amount: u64,
        payer: Address,
    ) -> Result<Self, TransactionError> {
        let max_parts = Shape::IN1_OUT8.n_outputs() as u8;
        if !(MIN_PARTS..=max_parts).contains(&num_outputs) {
            return Err(TransactionError::SplitInvalidPartCount { num_outputs });
        }
        if input.utxo.asset != asset {
            return Err(TransactionError::SplitInputAssetMismatch);
        }
        if input.utxo.zone_program_id.is_some() {
            return Err(TransactionError::SplitInputZoneMismatch);
        }
        if has_data(&input) {
            return Err(TransactionError::SplitInputHasData);
        }
        // The `.filter` already guarantees the product equals the input amount, so
        // discard the checked value once the mismatch case has been ruled out.
        per_output_amount
            .checked_mul(u64::from(num_outputs))
            .filter(|total| *total == input.utxo.amount)
            .ok_or(TransactionError::SplitAmountMismatch {
                input: input.utxo.amount,
                num_outputs,
                per_output: per_output_amount,
            })?;

        Ok(Self {
            owner,
            input,
            asset,
            num_outputs,
            per_output_amount,
            payer_pubkey_hash: sha256_be(payer.as_array()),
            blinding_seed: random_blinding(),
        })
    }

    /// Assemble the `IN1_OUT8` output set: `num_outputs` real self-owned utxos
    /// with blindings derived from the shared seed, followed by zero-value
    /// dummies that keep the padded output balance equal to the input.
    pub fn prepare(self) -> Result<PreparedSplit, TransactionError> {
        let slot_count = Shape::IN1_OUT8.n_outputs();
        let num_outputs = usize::from(self.num_outputs);

        let mut outputs = Vec::with_capacity(slot_count);
        for position in 0..num_outputs {
            outputs.push(SppProofOutputUtxo {
                owner_address: Some(self.owner),
                asset: self.asset,
                amount: self.per_output_amount,
                blinding: derive_blinding(&self.blinding_seed, position as u8),
                ..Default::default()
            });
        }
        for _ in num_outputs..slot_count {
            outputs.push(SppProofOutputUtxo {
                blinding: random_blinding(),
                owner_tag: Some(random_view_tag()?),
                ..Default::default()
            });
        }

        let first_nullifier = self.input.nullifier()?;

        Ok(PreparedSplit {
            owner: self.owner,
            input: self.input,
            outputs,
            first_nullifier,
            asset: self.asset,
            per_output_amount: self.per_output_amount,
            num_outputs: self.num_outputs,
            blinding_seed: self.blinding_seed,
            payer_pubkey_hash: self.payer_pubkey_hash,
        })
    }

    /// Keypair rail: assemble with the owner's own viewing key, seal the bundle
    /// at slot 0, and sign in place. The authority rail is [`Self::prepare`] +
    /// [`PreparedSplit::finalize`], with encryption/signing delegated to a
    /// `WalletAuthority`.
    pub fn sign<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SppProofInputs, TransactionError> {
        let prepared = self.prepare()?;
        let transaction_viewing_key =
            keypair.get_transaction_viewing_key(&prepared.first_nullifier)?;
        let salt = random_salt();
        let tx_viewing_pk = transaction_viewing_key.pubkey();

        let bundle_plaintext = prepared.bundle_plaintext(assets)?;
        let view_tag = prepared.owner_view_tag()?;
        let bundle = Split::encode_plaintext(
            &bundle_plaintext,
            view_tag,
            &SplitEncode {
                tx: transaction_viewing_key,
                recipient_pubkey: prepared.owner.viewing_pubkey,
                salt,
                slot_index: 0,
                blinding_seed: prepared.blinding_seed,
            },
        )?;

        let mut signed = prepared.finalize(tx_viewing_pk, salt, bundle)?;
        if keypair.curve()? == SignatureType::P256 {
            signed.sign_p256(keypair)?;
        }
        Ok(signed)
    }
}

pub struct PreparedSplit {
    pub owner: ShieldedAddress,
    pub input: SppProofInputUtxo,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub first_nullifier: [u8; 32],
    pub asset: Address,
    pub per_output_amount: u64,
    pub num_outputs: u8,
    pub blinding_seed: [u8; BLINDING_LEN],
    pub payer_pubkey_hash: [u8; 32],
}

impl PreparedSplit {
    /// The `Split` bundle plaintext that covers every real output: it carries
    /// the owner pubkey, the shared blinding seed, and the per-output amount, so
    /// the recipient re-derives all `num_outputs` utxos from slot 0 alone.
    pub fn bundle_plaintext(
        &self,
        assets: &AssetRegistry,
    ) -> Result<SplitBundlePlaintext, TransactionError> {
        Ok(SplitBundlePlaintext {
            owner_pubkey: self.owner.signing_pubkey,
            num_outputs: self.num_outputs,
            asset_id: assets.asset_id(&self.asset)?,
            asset_amount: self.per_output_amount,
            blinding_seed: self.blinding_seed,
            data: Data::default(),
        })
    }

    /// The owner's confidential view tag. It tags the bundle at slot 0 and every
    /// covered real output, and equals the bundle `view_tag` because the split
    /// is self-owned.
    pub fn owner_view_tag(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self.owner.signing_pubkey.confidential_view_tag()?)
    }

    /// Assemble [`SppProofInputs`] from the sealed slot-0 `bundle`. Slot 0
    /// publishes the single bundle ciphertext; the other real slots and every
    /// dummy slot are covered (`data == None`). Resolved owner tags pair 1:1
    /// with the outputs: the real slots share the owner view tag, and each dummy
    /// keeps its own random tag.
    ///
    /// KNOWN LIMITATION: those per-slot owner tags reveal the real output count
    /// N -- the N real tags cluster while the dummies do not. Hiding N cannot be
    /// done here: the real self-outputs must carry the owner tag to be spendable
    /// (the proof binds them), and the circuit rejects a zero-owner dummy tagged
    /// as a real owner, so uniform tags need a circuit change.
    pub fn finalize(
        self,
        tx_viewing_pk: P256Pubkey,
        salt: [u8; SALT_LEN],
        bundle: MessageData,
    ) -> Result<SppProofInputs, TransactionError> {
        let PreparedSplit {
            owner,
            input,
            outputs,
            num_outputs,
            payer_pubkey_hash,
            ..
        } = self;
        let owner_view_tag = owner.signing_pubkey.confidential_view_tag()?;
        let num_outputs = usize::from(num_outputs);

        let mut transact_outputs = Vec::with_capacity(outputs.len());
        let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
        for (position, output) in outputs.iter().enumerate() {
            let utxo_hash = output.hash()?;
            let (owner_tag, resolved, data) = if position == 0 {
                (
                    OwnerTag::Inline(bundle.view_tag),
                    bundle.view_tag,
                    Some(bundle.data.clone()),
                )
            } else if position < num_outputs {
                // Real self-output covered by the slot-0 bundle: no ciphertext,
                // owner view tag shared with the bundle.
                (OwnerTag::Inline(owner_view_tag), owner_view_tag, None)
            } else {
                // Zero-value dummy: its own random tag, no ciphertext.
                let tag = output.owner_tag.ok_or(TransactionError::MissingOutput)?;
                (OwnerTag::Inline(tag), tag, None)
            };
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag,
                data,
            });
            resolved_owner_tags.push(resolved);
        }

        let external_data = ExternalData::new(
            *tx_viewing_pk.as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
        );

        Ok(SppProofInputs {
            input_utxos: vec![input],
            output_utxos: outputs,
            external_data,
            payer_pubkey_hash,
            p256_signature: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use borsh::BorshDeserialize;
    use zolana_event::OutputDataEncoding;
    use zolana_keypair::ShieldedKeypair;

    use super::*;
    use crate::{
        serialization::DecodeCx, utxo::Utxo, EncryptedScheme, OwnerCx, SOL_MINT, VIEW_TAG_LEN,
    };

    fn split_input(keypair: &ShieldedKeypair, amount: u64) -> SppProofInputUtxo {
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding: [5u8; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        };
        SppProofInputUtxo::new(utxo, keypair)
    }

    fn assemble(keypair: &ShieldedKeypair, amount: u64, parts: u8) -> SppProofInputs {
        let owner = keypair.shielded_address().expect("shielded address");
        let split = ConfidentialSplit::new(
            owner,
            split_input(keypair, amount),
            SOL_MINT,
            parts,
            amount / u64::from(parts),
            Address::default(),
        )
        .expect("valid split");
        split
            .sign(keypair, &AssetRegistry::default())
            .expect("sign split")
    }

    fn split_error(
        keypair: &ShieldedKeypair,
        parts: u8,
        per_output: u64,
        amount: u64,
    ) -> TransactionError {
        let owner = keypair.shielded_address().unwrap();
        match ConfidentialSplit::new(
            owner,
            split_input(keypair, amount),
            SOL_MINT,
            parts,
            per_output,
            Address::default(),
        ) {
            Ok(_) => panic!("split construction unexpectedly succeeded"),
            Err(err) => err,
        }
    }

    #[test]
    fn split_out_of_range_part_count_is_rejected() {
        let keypair = ShieldedKeypair::new().unwrap();
        for parts in [0u8, 1, 9] {
            assert_eq!(
                split_error(&keypair, parts, 1, 800),
                TransactionError::SplitInvalidPartCount { num_outputs: parts }
            );
        }
    }

    #[test]
    fn split_amount_that_does_not_sum_to_input_is_rejected() {
        let keypair = ShieldedKeypair::new().unwrap();
        assert_eq!(
            split_error(&keypair, 3, 100, 800),
            TransactionError::SplitAmountMismatch {
                input: 800,
                num_outputs: 3,
                per_output: 100,
            }
        );
    }

    #[test]
    fn split_assembles_covered_bundle_with_padding() {
        let keypair = ShieldedKeypair::new().unwrap();
        let parts = 3u8;
        let per_output = 100u64;
        let amount = per_output * u64::from(parts);
        let signed = assemble(&keypair, amount, parts);

        // IN1_OUT8: one input, eight output slots.
        assert_eq!(signed.input_utxos.len(), 1);
        assert_eq!(signed.output_utxos.len(), Shape::IN1_OUT8.n_outputs());
        assert_eq!(
            signed.external_data.outputs.len(),
            Shape::IN1_OUT8.n_outputs()
        );

        // Balance: the real outputs sum to the input, dummies contribute zero.
        let out_sum: u128 = signed
            .output_utxos
            .iter()
            .map(|o| u128::from(o.amount))
            .sum();
        assert_eq!(out_sum, u128::from(amount));
        for output in signed.output_utxos.iter().take(usize::from(parts)) {
            assert_eq!(output.amount, per_output);
            assert_eq!(output.asset, SOL_MINT);
        }
        for output in signed.output_utxos.iter().skip(usize::from(parts)) {
            assert_eq!(output.amount, 0);
            assert!(output.is_dummy());
        }

        // Only slot 0 carries a ciphertext; every other slot is covered.
        let outputs = &signed.external_data.outputs;
        assert!(outputs.first().and_then(|o| o.data.as_ref()).is_some());
        for output in outputs.iter().skip(1) {
            assert!(output.data.is_none());
        }

        // Resolved owner tags pair 1:1; the real slots share the owner tag.
        let owner_tag = keypair.signing_pubkey().confidential_view_tag().unwrap();
        assert_eq!(
            signed.external_data.resolved_owner_tags.len(),
            outputs.len()
        );
        for resolved in signed
            .external_data
            .resolved_owner_tags
            .iter()
            .take(usize::from(parts))
        {
            assert_eq!(*resolved, owner_tag);
        }
        for resolved in signed
            .external_data
            .resolved_owner_tags
            .iter()
            .skip(usize::from(parts))
        {
            assert_ne!(*resolved, owner_tag);
        }
    }

    #[test]
    fn split_bundle_round_trips_to_output_hashes() {
        let keypair = ShieldedKeypair::new().unwrap();
        let parts = 3u8;
        let per_output = 100u64;
        let amount = per_output * u64::from(parts);
        let signed = assemble(&keypair, amount, parts);

        // Recover the slot-0 bundle ciphertext.
        let slot0 = signed.external_data.outputs.first().expect("slot 0");
        let payload = slot0.data.as_ref().expect("bundle ciphertext");
        let OutputDataEncoding::Encrypted(blob) =
            OutputDataEncoding::try_from_slice(payload).expect("output data encoding")
        else {
            panic!("split bundle must be an encrypted output");
        };
        let (&scheme_byte, body) = blob.split_first().expect("scheme byte");
        assert_eq!(scheme_byte, EncryptedScheme::Split.as_byte());

        let tx_viewing_pk =
            P256Pubkey::from_bytes(signed.external_data.tx_viewing_pk).expect("tx viewing pk");
        let cx = DecodeCx {
            viewing_key: &keypair.viewing_key,
            tx_viewing_pk: Some(tx_viewing_pk),
            salt: Some(signed.external_data.salt),
            slot_index: 0,
            first_nullifier: None,
        };
        let plaintext = Split::decode(body, &cx).expect("decode split bundle");
        assert_eq!(plaintext.num_outputs, parts);

        let owner_cx = OwnerCx {
            owner: keypair.signing_pubkey(),
            assets: &AssetRegistry::default(),
            zone_program_id: None,
        };
        let recovered = Split::into_utxos(plaintext, &owner_cx).expect("into utxos");
        assert_eq!(recovered.len(), usize::from(parts));

        // Each recovered utxo's commitment matches the on-chain output hash at
        // its slot.
        let nullifier_pk = keypair.nullifier_key.pubkey().expect("nullifier pk");
        let zero = [0u8; VIEW_TAG_LEN];
        for (position, utxo) in recovered.iter().enumerate() {
            let recovered_hash = utxo
                .hash(&nullifier_pk, &zero, &zero)
                .expect("recovered hash");
            let on_chain_hash = signed
                .output_utxos
                .get(position)
                .expect("output slot")
                .hash()
                .expect("on-chain hash");
            assert_eq!(recovered_hash, on_chain_hash);
        }
    }
}
