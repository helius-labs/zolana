use num_bigint::BigUint;
use solana_address::Address;
use zolana_interface::{MAX_INTERFACE_TRANSFERS, N_PUBLIC_SLOTS, SOL_ASSET_FIELD};
use zolana_keypair::{hash::sha256, random_blinding, Curve, ViewingKey, ViewingKeyTrait};

use super::{
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    types::PrivateTxHash,
};
use crate::{
    error::TransactionError,
    instructions::types::{InputUtxoContext, SppProofInputUtxo},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
    ExternalData, SppProofOutputUtxo, SOL_MINT,
};

pub const BN254_MODULUS_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

fn modulus() -> BigUint {
    BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("valid BN254 modulus literal")
}

fn right_align_slice(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[32 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
    out
}

pub fn signed_to_field(value: i64) -> [u8; 32] {
    signed_magnitude_to_field(value >= 0, value.unsigned_abs())
}

pub fn signed_magnitude_to_field(is_deposit: bool, amount: u64) -> [u8; 32] {
    if amount == 0 {
        return [0u8; 32];
    }
    let magnitude = BigUint::from(amount);
    let field = if is_deposit {
        magnitude
    } else {
        modulus() - magnitude
    };
    right_align_slice(&field.to_bytes_be())
}

pub fn asset_field(asset: &Address) -> Result<[u8; 32], TransactionError> {
    Ok(zolana_hasher::primitives::hash_bytes(asset.as_array())?)
}

pub fn inputs_require_p256(inputs: &[SppProofInputUtxo]) -> Result<bool, TransactionError> {
    for spend in inputs {
        // A dummy's zero owner reads as P256; skip it so it never forces the
        // removed P256 rail.
        if spend.is_dummy() {
            continue;
        }
        if spend.utxo.owner.curve()? == Curve::P256 {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn first_nullifier(input_utxos: &[SppProofInputUtxo]) -> Result<[u8; 32], TransactionError> {
    input_utxos
        .first()
        .ok_or(TransactionError::NoInputs)?
        .nullifier()
}

/// Assigns the final deterministic blinding to every physical output slot.
/// Call this before hashing or encrypting any output.
pub fn assign_output_blindings(
    outputs: &mut [SppProofOutputUtxo],
    first_nullifier: &[u8; 32],
    seed: &[u8; 32],
) -> Result<(), TransactionError> {
    for (index, output) in outputs.iter_mut().enumerate() {
        let index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
        output.blinding = derive_transact_output_blinding(first_nullifier, seed, index)?;
    }
    Ok(())
}

/// Draws the transaction secret, derives the output blinding seed from it, and
/// assigns every final output blinding. Call this before hashing or encrypting
/// the outputs; the returned secret goes into
/// [`SppProofInputs::tx_secret`](SppProofInputs) and is disclosed to nobody.
pub fn prepare_output_blindings(
    input_utxos: &[SppProofInputUtxo],
    outputs: &mut [SppProofOutputUtxo],
) -> Result<[u8; 32], TransactionError> {
    let tx_secret = random_blinding();
    let first_nullifier = first_nullifier(input_utxos)?;
    let seed = derive_output_blinding_seed(&first_nullifier, &tx_secret)?;
    assign_output_blindings(outputs, &first_nullifier, &seed)?;
    Ok(tx_secret)
}

pub fn get_transaction_viewing_key<K: ViewingKeyTrait>(
    keypair: &K,
    input_utxos: &[SppProofInputUtxo],
) -> Result<ViewingKey, TransactionError> {
    let first_nullifier = first_nullifier(input_utxos)?;
    Ok(keypair.get_transaction_viewing_key(&first_nullifier)?)
}

/// Uniform public transfer slots: ordered interface transfers are accumulated per
/// asset in first-appearance order. The circuit pins an idle slot to `(0, 0)`, so
/// legs whose net for one asset returns to zero are rejected (they could never be
/// proven); only never-assigned slots stay `(0, 0)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicTransfers {
    pub assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub amounts: [[u8; 32]; N_PUBLIC_SLOTS],
}

impl PublicTransfers {
    pub fn interleaved(&self) -> [[u8; 32]; 2 * N_PUBLIC_SLOTS] {
        core::array::from_fn(|index| {
            let slot = index / 2;
            if index % 2 == 0 {
                self.assets.get(slot).copied().unwrap_or_default()
            } else {
                self.amounts.get(slot).copied().unwrap_or_default()
            }
        })
    }
}

#[derive(Clone)]
pub struct SppProofInputs {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxos: Vec<SppProofOutputUtxo>,
    /// The transaction's single private random value. The output blinding seed
    /// and the private transaction blinding derive from it and the first
    /// nullifier, and neither child can be inverted back to it, so disclosing
    /// one child never reaches the other. The secret itself stays private: the
    /// prover receives it, nobody else does.
    pub tx_secret: [u8; 32],
    /// Raw id of the tree every output is appended to.
    // TODO(tree-id): resolve the tree id from the tree account.
    pub output_tree_id: u16,
    pub external_data: ExternalData,
    pub payer: Address,
}

impl SppProofInputs {
    /// Starts with a zero `tx_secret` and output tree `0`. The circuit derives
    /// every output blinding from `tx_secret`, so a caller that assigns its own
    /// outputs must blind them with [`prepare_output_blindings`] and pass the
    /// returned secret through [`Self::with_tx_secret`], or the proof fails.
    pub fn new(
        input_utxos: Vec<SppProofInputUtxo>,
        output_utxos: Vec<SppProofOutputUtxo>,
        external_data: ExternalData,
        payer: Address,
    ) -> Self {
        Self {
            input_utxos,
            output_utxos,
            tx_secret: [0u8; 32],
            output_tree_id: 0,
            external_data,
            payer,
        }
    }

    #[must_use]
    pub fn with_tx_secret(mut self, tx_secret: [u8; 32]) -> Self {
        self.tx_secret = tx_secret;
        self
    }

    #[must_use]
    pub fn with_output_tree_id(mut self, output_tree_id: u16) -> Self {
        self.output_tree_id = output_tree_id;
        self
    }

    /// Nullifier of the first input slot, which must be a real spend. It enters
    /// the nullifier tree once, so it makes every value derived from
    /// [`Self::tx_secret`] unique to one accepted transaction.
    pub fn first_nullifier(&self) -> Result<[u8; 32], TransactionError> {
        first_nullifier(&self.input_utxos)
    }

    /// Seed every physical output blinding derives from. Disclosed to the
    /// reader of an anonymous Sender bundle or a plaintext transfer.
    pub fn output_blinding_seed(&self) -> Result<[u8; 32], TransactionError> {
        derive_output_blinding_seed(&self.first_nullifier()?, &self.tx_secret)
    }

    /// Final `private_tx_hash` preimage element. Disclosed only to a policy or
    /// third-party co-prover that has to recompute the transaction hash.
    pub fn private_tx_blinding(&self) -> Result<[u8; 32], TransactionError> {
        derive_private_tx_blinding(&self.first_nullifier()?, &self.tx_secret)
    }

    /// Unique non-payer Ed25519 and PDA input owners in first-input order. This
    /// is the account vector appended by the high-level instruction builder; the
    /// program applies the same payer-seeded first-occurrence normalization. A
    /// PDA owner occupies an owner-signer slot like any Ed25519 owner; the
    /// owning program flips its account to signer via CPI, so only wallet
    /// signature collection treats it differently.
    pub fn owner_signer_pubkeys(&self) -> Result<Vec<Address>, TransactionError> {
        let mut signers = Vec::new();
        let mut signer_hashes: Vec<[u8; 32]> = Vec::new();
        for spend in self.input_utxos.iter().filter(|spend| !spend.is_dummy()) {
            let address = match spend.utxo.owner.curve()? {
                Curve::P256 => continue,
                Curve::Ed25519 | Curve::Pda => {
                    Address::new_from_array(spend.utxo.owner.confidential_view_tag()?)
                }
            };
            let hash = spend.utxo.owner.owner_proof_input_hash()?;
            if address == self.payer || signer_hashes.contains(&hash) {
                continue;
            }
            signer_hashes.push(hash);
            signers.push(address);
        }
        Ok(signers)
    }

    /// Fixed-width signer identity vector committed by the circuit. The payer
    /// occupies slot zero, followed by unique non-payer input owners. Every
    /// signer is a Solana account, so each identity carries the Solana owner
    /// tag; the program derives the same values from its signer accounts.
    pub fn signer_pk_hashes(&self, width: usize) -> Result<Vec<[u8; 32]>, TransactionError> {
        let mut hashes = vec![zolana_hasher::primitives::solana_owner_identity(
            self.payer.as_array(),
        )?];
        hashes.extend(
            self.owner_signer_pubkeys()?
                .iter()
                .map(|signer| zolana_hasher::primitives::solana_owner_identity(signer.as_array()))
                .collect::<Result<Vec<_>, _>>()?,
        );
        if hashes.len() > width {
            return Err(TransactionError::UnsupportedShape {
                n_in: self.input_utxos.len(),
                n_out: self.output_utxos.len(),
            });
        }
        hashes.resize(width, [0u8; 32]);
        Ok(hashes)
    }

    pub fn check_shape(&self) -> Result<Shape, TransactionError> {
        let n_in = self.input_utxos.len();
        let n_out = self.output_utxos.len();
        SPP_SUPPORTED_SHAPES
            .into_iter()
            .find(|shape| shape.n_inputs() == n_in && shape.n_outputs() == n_out)
            .ok_or(TransactionError::UnsupportedShape { n_in, n_out })
    }

    pub fn public_transfers(&self) -> Result<PublicTransfers, TransactionError> {
        if self.external_data.interface_transfers.len() > MAX_INTERFACE_TRANSFERS {
            return Err(TransactionError::TooManyInterfaceTransfers {
                got: self.external_data.interface_transfers.len(),
                max: MAX_INTERFACE_TRANSFERS,
            });
        }

        let mut aggregated: Vec<(Address, i128)> = Vec::new();
        for transfer in &self.external_data.interface_transfers {
            let asset = transfer.asset();
            let amount = transfer.amount();
            if amount == 0 {
                return Err(TransactionError::ZeroInterfaceTransferAmount);
            }
            if transfer.interface_transfer().is_spl() && asset == SOL_MINT {
                return Err(TransactionError::SettlementTargetMismatch { asset });
            }
            let magnitude = i128::from(amount);
            let signed = if transfer.is_deposit() {
                magnitude
            } else {
                -magnitude
            };
            if let Some((_, total)) = aggregated
                .iter_mut()
                .find(|(existing, _)| *existing == asset)
            {
                *total = total
                    .checked_add(signed)
                    .ok_or(TransactionError::PublicTransferOverflow { asset })?;
                u64::try_from(total.unsigned_abs())
                    .map_err(|_| TransactionError::PublicTransferOverflow { asset })?;
            } else {
                aggregated.push((asset, signed));
            }
        }
        if let Some((asset, _)) = aggregated.iter().find(|(_, total)| *total == 0) {
            return Err(TransactionError::ZeroNetInterfaceTransferAmount { asset: *asset });
        }
        if aggregated.len() > N_PUBLIC_SLOTS {
            return Err(TransactionError::TooManyPublicAssets {
                got: aggregated.len(),
                max: N_PUBLIC_SLOTS,
            });
        }

        let mut transfers = PublicTransfers::default();
        for ((asset_slot, amount_slot), (asset, amount)) in transfers
            .assets
            .iter_mut()
            .zip(transfers.amounts.iter_mut())
            .zip(aggregated)
        {
            let magnitude = u64::try_from(amount.unsigned_abs())
                .map_err(|_| TransactionError::PublicTransferOverflow { asset })?;
            *asset_slot = if asset == SOL_MINT {
                SOL_ASSET_FIELD
            } else {
                asset_field(&asset)?
            };
            *amount_slot = signed_magnitude_to_field(amount > 0, magnitude);
        }
        Ok(transfers)
    }

    /// Nullifiers of the padding (dummy) input slots, in slot order. The circuit
    /// checks nullifier non-inclusion for every slot, so each dummy needs a real
    /// low-element witness fetched for its own nullifier.
    pub fn dummy_nullifiers(&self) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.input_utxos
            .iter()
            .filter(|spend| spend.is_dummy())
            .map(|spend| spend.nullifier())
            .collect()
    }

    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        self.input_utxos
            .iter()
            .filter(|spend| !spend.is_dummy())
            .enumerate()
            .map(|(index, spend)| {
                Ok(InputUtxoContext {
                    index,
                    utxo_hash: spend.hash()?,
                    nullifier: spend.nullifier()?,
                })
            })
            .collect()
    }

    pub fn message_hash(&self) -> Result<[u8; 32], TransactionError> {
        // Dummies contribute zero to match circuit private_tx hashing.
        let mut input_hashes = Vec::with_capacity(self.input_utxos.len());
        for spend in &self.input_utxos {
            if spend.is_dummy() {
                input_hashes.push([0u8; 32]);
            } else {
                input_hashes.push(spend.hash()?);
            }
        }

        let mut output_hashes = Vec::with_capacity(self.output_utxos.len());
        for output in &self.output_utxos {
            if output.is_dummy() {
                output_hashes.push([0u8; 32]);
            } else {
                output_hashes.push(output.hash(self.output_tree_id)?);
            }
        }

        let external_data_hash = self.external_data.hash()?;
        let private_tx = PrivateTxHash::new(
            &input_hashes,
            &output_hashes,
            &external_data_hash,
            &self.private_tx_blinding()?,
        )
        .hash()?;
        Ok(sha256(&private_tx))
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::{NullifierKey, ShieldedKeypair, ShieldedPda, SigningKey, ViewingKey};

    use super::*;
    use crate::{Data, Utxo};

    fn ed25519_keypair(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
            .expect("Ed25519 keypair")
    }

    fn input(keypair: &ShieldedKeypair) -> SppProofInputUtxo {
        SppProofInputUtxo::new(
            Utxo {
                owner: keypair.signing_pubkey(),
                asset: SOL_MINT,
                amount: 1,
                blinding: [7u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            keypair,
        )
    }

    #[test]
    fn pda_owner_is_an_owner_signer_and_committed_signer_hash() {
        let payer = ed25519_keypair(3);
        let payer_address = Address::new_from_array(
            payer
                .signing_pubkey()
                .as_ed25519()
                .expect("payer Ed25519 pubkey"),
        );
        let pda = Address::new_from_array([5u8; 32]);
        let identity = ShieldedPda::with_viewing_key(
            pda,
            NullifierKey::from_secret([3u8; 31]),
            ViewingKey::new(),
        );
        let pda_input = SppProofInputUtxo::new(
            Utxo {
                owner: identity.signing_pubkey(),
                asset: SOL_MINT,
                amount: 1,
                blinding: [7u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &identity,
        );
        let proof_inputs = SppProofInputs::new(
            vec![input(&payer), pda_input],
            Vec::new(),
            ExternalData::new([0u8; 33], [0u8; 16], Vec::new(), Vec::new(), Vec::new()),
            payer_address,
        );

        assert_eq!(proof_inputs.owner_signer_pubkeys().unwrap(), vec![pda]);
        assert_eq!(
            proof_inputs.signer_pk_hashes(3).unwrap(),
            vec![
                payer
                    .signing_pubkey()
                    .owner_proof_input_hash()
                    .expect("payer owner hash"),
                identity
                    .signing_pubkey()
                    .owner_proof_input_hash()
                    .expect("pda owner hash"),
                [0u8; 32],
            ]
        );
    }

    #[test]
    fn signer_vector_is_payer_seeded_deduplicated_and_zero_padded() {
        let payer = ed25519_keypair(3);
        let other = ed25519_keypair(9);
        let payer_address = Address::new_from_array(
            payer
                .signing_pubkey()
                .as_ed25519()
                .expect("payer Ed25519 pubkey"),
        );
        let proof_inputs = SppProofInputs::new(
            vec![
                input(&payer),
                input(&other),
                input(&other),
                SppProofInputUtxo::new_dummy(),
            ],
            Vec::new(),
            ExternalData::new([0u8; 33], [0u8; 16], Vec::new(), Vec::new(), Vec::new()),
            payer_address,
        );

        let signers = proof_inputs.owner_signer_pubkeys().unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(
            signers[0],
            Address::new_from_array(
                other
                    .signing_pubkey()
                    .as_ed25519()
                    .expect("other Ed25519 pubkey"),
            )
        );

        let hashes = proof_inputs.signer_pk_hashes(5).unwrap();
        assert_eq!(
            hashes,
            vec![
                payer
                    .signing_pubkey()
                    .owner_proof_input_hash()
                    .expect("payer owner hash"),
                other
                    .signing_pubkey()
                    .owner_proof_input_hash()
                    .expect("other owner hash"),
                [0u8; 32],
                [0u8; 32],
                [0u8; 32],
            ]
        );
    }
}
