//! High-level merge build, separated from the prover the same way [`Transaction`]
//! and [`AssembledTransfer`] separate transfer assembly from
//! [`crate::prover::transfer_p256`]. [`Merge`] names which UTXOs to consolidate
//! and the derived output; it carries no Merkle proofs and no dummy padding.
//! Converting it into [`PreparedMerge`] does the padding to [`MERGE_INPUTS`], and
//! [`PreparedMerge::into_prover`] folds in the proofs to produce a [`MergeProver`].
//! Merge proves ownership in-circuit from the nullifier secret, so there is no
//! signing step.
//!
//! [`Transaction`]: crate::private_transaction::Transaction
//! [`AssembledTransfer`]: crate::private_transaction::AssembledTransfer

use p256::SecretKey;
use zolana_keypair::{
    shielded::ShieldedKeypair, viewing_key::random_blinding, NullifierKey, P256Pubkey, PublicKey,
};
use zolana_transaction::OutputUtxo;

use crate::{
    error::ClientError,
    private_transaction::transaction::{InputCommitment, SpendProof, SpendUtxo},
    prover::{merge_p256::MergeProver, transfer_p256::TransferSpendInput},
};

/// Fixed input arity of the merge circuit (`merge_8_1`). Real inputs sit at the
/// front; padding fills the rest with dummies.
pub const MERGE_INPUTS: usize = 8;

/// A merge plan: the real UTXOs to consolidate (no Merkle proofs, no padding), the
/// derived single output, and the owner identity. Every input must share one owner
/// (P256 or Solana), asset, and nullifier secret.
pub struct Merge {
    inputs: Vec<SpendUtxo>,
    output: OutputUtxo,
    expiry_unix_ts: u64,
    signing_pubkey: PublicKey,
    nullifier_key: NullifierKey,
    user_viewing_pk: P256Pubkey,
    tx_viewing_sk: SecretKey,
}

impl Merge {
    /// Validate the inputs, derive the merged output, and capture the owner
    /// identity. Takes the keypair (not a signature) because the circuit needs the
    /// nullifier secret and the viewing key for the verifiable encryption; it never
    /// signs.
    pub fn new(keypair: &ShieldedKeypair, inputs: Vec<SpendUtxo>) -> Result<Self, ClientError> {
        if inputs.is_empty() {
            return Err(ClientError::NoInputs);
        }
        if inputs.len() > MERGE_INPUTS {
            return Err(ClientError::TooManyInputs {
                got: inputs.len(),
                max: MERGE_INPUTS,
            });
        }

        let asset = inputs.first().ok_or(ClientError::NoInputs)?.utxo.asset;
        // The proof binds every input to one shared owner identity, so the merge
        // rail is the owner keypair's rail and every input must match it.
        let owner_rail = keypair.signing_pubkey().signature_type()?;
        let mut total = 0u64;
        for (index, spend) in inputs.iter().enumerate() {
            if spend.utxo.owner.signature_type()? != owner_rail {
                return Err(ClientError::MergeInputRailMismatch { index });
            }
            if spend.utxo.asset != asset {
                return Err(ClientError::MergeInputAssetMismatch { index });
            }
            total = total
                .checked_add(spend.utxo.amount)
                .ok_or(ClientError::SelectedBalanceOverflow)?;
        }

        let output = OutputUtxo {
            owner_hash: keypair.owner_hash()?,
            asset,
            amount: total,
            blinding: random_blinding(),
            ..Default::default()
        };

        // Ephemeral viewing scalar: 31 random bytes are < BN254 modulus, so the
        // value is both a valid P-256 scalar and a valid circuit witness.
        let mut sk_bytes = [0u8; 32];
        sk_bytes[1..].copy_from_slice(&random_blinding());
        let tx_viewing_sk = SecretKey::from_slice(&sk_bytes)
            .map_err(|e| ClientError::P256Signature(e.to_string()))?;

        Ok(Self {
            inputs,
            output,
            // Never expires by default; `merge_transact` rejects `current_ts >
            // expiry`, so set this explicitly for a relayer deadline.
            expiry_unix_ts: u64::MAX,
            signing_pubkey: keypair.signing_pubkey(),
            nullifier_key: keypair.nullifier_key.clone(),
            user_viewing_pk: keypair.viewing_pubkey(),
            tx_viewing_sk,
        })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }
}

/// A merge padded to [`MERGE_INPUTS`] (real inputs first, dummies at the tail),
/// still proofless. [`Self::input_commitments`] yields what to fetch Merkle proofs
/// for and [`Self::into_prover`] folds them in.
pub struct PreparedMerge {
    inputs: Vec<SpendUtxo>,
    output: OutputUtxo,
    expiry_unix_ts: u64,
    signing_pubkey: PublicKey,
    nullifier_key: NullifierKey,
    user_viewing_pk: P256Pubkey,
    tx_viewing_sk: SecretKey,
}

impl From<Merge> for PreparedMerge {
    fn from(merge: Merge) -> Self {
        let Merge {
            mut inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            user_viewing_pk,
            tx_viewing_sk,
        } = merge;
        while inputs.len() < MERGE_INPUTS {
            inputs.push(SpendUtxo::new_dummy());
        }
        Self {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            user_viewing_pk,
            tx_viewing_sk,
        }
    }
}

impl PreparedMerge {
    /// Commitments for the real inputs only; dummy padding has a zero owner and no
    /// meaningful commitment to look up.
    pub fn input_commitments(&self) -> Result<Vec<InputCommitment>, ClientError> {
        self.inputs
            .iter()
            .filter(|spend| !spend.is_dummy())
            .enumerate()
            .map(|(index, spend)| {
                let utxo_hash =
                    spend
                        .utxo
                        .hash(&spend.witness.nullifier_pubkey, &[0u8; 32], &[0u8; 32])?;
                let nullifier = spend.witness.nullifier;
                Ok(InputCommitment {
                    index,
                    utxo_hash,
                    nullifier,
                })
            })
            .collect()
    }

    /// Attach the real-input Merkle proofs (in `input_commitments` order) and
    /// produce the prover. Each dummy slot (zero owner) is proofless and mirrors
    /// the first real input's roots downstream.
    pub fn into_prover(self, input_proofs: &[SpendProof]) -> Result<MergeProver, ClientError> {
        let PreparedMerge {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            user_viewing_pk,
            tx_viewing_sk,
        } = self;

        let mut spends = Vec::with_capacity(inputs.len());
        let mut real_index = 0;
        for spend in inputs {
            let SpendUtxo { utxo, witness } = spend;
            let proof = if utxo.owner.is_zero() {
                None
            } else {
                let proof = input_proofs
                    .get(real_index)
                    .ok_or(ClientError::MissingInputMerkleProof { index: real_index })?
                    .clone();
                real_index += 1;
                Some(proof)
            };
            spends.push(TransferSpendInput {
                utxo,
                witness,
                proof,
            });
        }

        Ok(MergeProver {
            inputs: spends,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            user_viewing_pk,
            tx_viewing_sk,
        })
    }
}
