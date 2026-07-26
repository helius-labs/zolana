use ark_bn254::Fr;
use ark_ff::PrimeField;
use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{error::ProgramError, ProgramResult};
use tinyvec::ArrayVec;
use zolana_hasher::{Hasher, Sha256};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{
        CircuitType, TransactIxDataRef, TransactProof as ProofData,
    },
    verifying_keys::{
        transfer_confidential_1_1, transfer_confidential_1_2, transfer_confidential_1_8,
        transfer_confidential_2_2, transfer_confidential_2_3, transfer_confidential_3_3,
        transfer_confidential_4_3, transfer_confidential_4_4, transfer_confidential_5_3,
        transfer_confidential_5_4, transfer_p256_confidential_1_1, transfer_p256_confidential_1_2,
        transfer_p256_confidential_1_8, transfer_p256_confidential_2_2,
        transfer_p256_confidential_2_3, transfer_p256_confidential_3_3,
        transfer_p256_confidential_4_3, transfer_p256_confidential_4_4,
        transfer_p256_confidential_5_3, transfer_p256_confidential_5_4, transfer_p256_zone_1_1,
        transfer_p256_zone_1_2, transfer_p256_zone_1_8, transfer_p256_zone_2_2,
        transfer_p256_zone_2_3, transfer_p256_zone_3_3, transfer_p256_zone_4_3,
        transfer_p256_zone_4_4, transfer_p256_zone_5_3, transfer_p256_zone_5_4, transfer_zone_1_1,
        transfer_zone_1_2, transfer_zone_1_8, transfer_zone_2_2, transfer_zone_2_3,
        transfer_zone_3_3, transfer_zone_4_3, transfer_zone_4_4, transfer_zone_5_3,
        transfer_zone_5_4, transfer_zone_authority_1_1, transfer_zone_authority_2_2,
        transfer_zone_authority_3_3, transfer_zone_authority_4_4,
    },
    N_PUBLIC_SLOTS,
};

use crate::instructions::verifier;

pub const MAX_INPUTS: usize = 5;

pub const MAX_OUTPUTS: usize = 8;

pub const P256_OWNED_SIGNER: u8 = 255;

#[derive(Default, Debug)]
pub struct TransactProofInputs {
    pub utxo_roots: [[u8; 32]; MAX_INPUTS],
    pub nullifier_tree_roots: [[u8; 32]; MAX_INPUTS],
    pub input_owner_pk_hashes: [[u8; 32]; MAX_INPUTS],
    pub output_owner_pk_hashes: [[u8; 32]; MAX_OUTPUTS],
    pub p256_signing_pk_field: [u8; 32],
    pub external_data_hash: [u8; 32],
    pub public_slot_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_slot_amounts: [i128; N_PUBLIC_SLOTS],
    pub zone_program_id: [u8; 32],
    pub payer_pubkey_hash: [u8; 32],
    pub allow_dummy_inputs: [u8; 32],
}

pub struct TransactProof<'a> {
    ix: &'a TransactIxDataRef<'a>,
    // Borrowed, not owned: `TransactProofInputs` is ~1 KB of fixed arrays. Holding
    // it by value would copy it onto the caller's stack frame (on top of the
    // owner's copy) and overflow the SBF 4 KB frame limit, so the verifier reads it
    // through a reference instead.
    derived: &'a TransactProofInputs,
}

impl<'a> TransactProof<'a> {
    pub fn new(ix: &'a TransactIxDataRef<'a>, derived: &'a TransactProofInputs) -> Self {
        Self { ix, derived }
    }

    /// `IS_ZONE` / `IS_AUTHORITY` are fixed by the calling instruction, not by
    /// attacker-supplied data: `transact` verifies with `<false, false>`
    /// (confidential keys), `zone_transact` with `<true, false>` (anonymous keys),
    /// `zone_authority_transact` with `<true, true>` (zone-authority keys). This is
    /// what enforces that only the matching path can use a given key family.
    /// The `circuit` selector in the instruction data must agree with both the
    /// instruction (type) and the data (variant); the selector itself only picks
    /// the verifying key, it is not a public input.
    #[inline(never)]
    pub fn verify<const IS_ZONE: bool, const IS_AUTHORITY: bool>(&self) -> ProgramResult {
        self.check_selector::<IS_ZONE, IS_AUTHORITY>()?;
        let public_input_hash = self.public_input_hash::<IS_ZONE, IS_AUTHORITY>()?;
        let is_p256 = self.is_p256();
        let (n_in, n_out) = (self.n_inputs(), self.n_outputs());
        // `committed` ties the proof format to the circuit: the P256 rail is
        // BSB22-committed, the eddsa rail and the vanilla zone-authority circuit
        // are not. The zone-authority instantiation is one key per shape (no rail
        // split): it recomputes each owner `pk_field` from the witnessed point.
        let (verifying_key, committed) = if IS_AUTHORITY {
            (select_zone_authority_verifying_key(n_in, n_out)?, false)
        } else {
            let vk = match (IS_ZONE, is_p256) {
                (true, true) => select_zone_verifying_key::<true>(n_in, n_out)?,
                (true, false) => select_zone_verifying_key::<false>(n_in, n_out)?,
                (false, true) => select_confidential_verifying_key::<true>(n_in, n_out)?,
                (false, false) => select_confidential_verifying_key::<false>(n_in, n_out)?,
            };
            (vk, is_p256)
        };
        let encoding_err = ShieldedPoolError::InvalidTransactProofEncoding;
        let verify_err = ShieldedPoolError::TransactProofVerificationFailed;
        // The proof variant must agree with the circuit: a committed circuit (the
        // P256 rail) carries the BSB22 commitment; a vanilla circuit (the eddsa
        // rail or the zone-authority instantiation) does not.
        let proof = match (&self.ix.proof, committed) {
            (ProofData::Eddsa { a, b, c }, false) => verifier::CompressedGroth16Proof {
                a,
                b,
                c,
                commitment: None,
            },
            (ProofData::P256(p), true) => verifier::CompressedGroth16Proof {
                a: &p.a,
                b: &p.b,
                c: &p.c,
                commitment: Some((&p.commitment, &p.commitment_pok)),
            },
            _ => return Err(ShieldedPoolError::MismatchedTransactProofVariant.into()),
        };
        verifier::verify_groth16(
            proof,
            public_input_hash,
            verifying_key,
            encoding_err,
            verify_err,
        )
    }

    /// Fail-closed consistency of the declared circuit selector: its type must
    /// match the dispatched instruction, and its variant must match
    /// `p256_signing_pk_x` (present on the P256 variant only).
    fn check_selector<const IS_ZONE: bool, const IS_AUTHORITY: bool>(&self) -> ProgramResult {
        let expected = match (IS_ZONE, IS_AUTHORITY) {
            (false, false) => CircuitType::Confidential,
            (true, false) => CircuitType::Zone,
            // The authority instantiation is a zone circuit; (<false, true>) is
            // never instantiated, map it to the authority type as well.
            (_, true) => CircuitType::ZoneAuthority,
        };
        if self.ix.circuit.circuit_type() != expected {
            return Err(ShieldedPoolError::MismatchedCircuitType.into());
        }
        if self.is_p256() != self.ix.p256_signing_pk_x.is_some() {
            return Err(ShieldedPoolError::MismatchedCircuitVariant.into());
        }
        Ok(())
    }

    fn n_inputs(&self) -> usize {
        self.ix.inputs.len()
    }

    fn n_outputs(&self) -> usize {
        self.ix.outputs.len()
    }

    /// The proving variant comes from the declared circuit selector (validated
    /// by [`Self::check_selector`]), not from the input signer indices.
    fn is_p256(&self) -> bool {
        self.ix.circuit.is_p256()
    }

    #[inline(never)]
    fn public_input_hash<const IS_ZONE: bool, const IS_AUTHORITY: bool>(
        &self,
    ) -> Result<[u8; 32], ProgramError> {
        let n_in = self.n_inputs();
        let n_out = self.n_outputs();
        let shape = ShieldedPoolError::InvalidTransactShape;
        let utxo_roots = self.derived.utxo_roots.get(..n_in).ok_or(shape)?;
        let nullifier_tree_roots = self.derived.nullifier_tree_roots.get(..n_in).ok_or(shape)?;
        let input_owner_pk_hashes = self
            .derived
            .input_owner_pk_hashes
            .get(..n_in)
            .ok_or(shape)?;
        let output_owner_pk_hashes = self
            .derived
            .output_owner_pk_hashes
            .get(..n_out)
            .ok_or(shape)?;

        let p256_message_hash = if self.is_p256() {
            sha256(self.ix.private_tx_hash)?
        } else {
            [0u8; 32]
        };

        // Mirrors `shared.Transaction.publicInputHash` (Go): a shared base
        // every variant shares, then the variant-dependent tail — the P256 message
        // (`Poseidon(0, 0)` on the Solana-only rails), then `input_owner_pk_hashes`
        // for every variant except the zone-authority one (owners stay private and
        // do not sign), then the confidential appendix (`output_owner_pk_hashes`,
        // `p256_signing_pk_field`) only for the confidential (non-zone) variant.
        let mut fields: ArrayVec<[[u8; 32]; 20]> = ArrayVec::new();
        fields.extend_from_slice(&[
            self.nullifier_chain()?,
            self.output_chain()?,
            hash_chain(utxo_roots)?,
            hash_chain(nullifier_tree_roots)?,
            *self.ix.private_tx_hash,
            self.derived.external_data_hash,
        ]);
        for (asset, amount) in self
            .derived
            .public_slot_assets
            .iter()
            .zip(self.derived.public_slot_amounts.iter())
        {
            fields.push(*asset);
            fields.push(amount_field(*amount)?);
        }
        fields.extend_from_slice(&[
            self.derived.zone_program_id,
            self.derived.payer_pubkey_hash,
            self.derived.allow_dummy_inputs,
            hash_field(&p256_message_hash)?,
        ]);
        if !IS_AUTHORITY {
            fields.push(hash_chain(input_owner_pk_hashes)?);
        }
        if !IS_ZONE {
            fields.push(hash_chain(output_owner_pk_hashes)?);
            fields.push(self.derived.p256_signing_pk_field);
        }
        hash_chain(fields.as_slice())
    }

    fn nullifier_chain(&self) -> Result<[u8; 32], ProgramError> {
        let mut iter = self.ix.inputs.iter();
        let Some(first) = iter.next() else {
            return Ok([0u8; 32]);
        };
        let mut acc = first.nullifier_hash;
        for input in iter {
            acc = poseidon2(&acc, &input.nullifier_hash)?;
        }
        Ok(acc)
    }

    fn output_chain(&self) -> Result<[u8; 32], ProgramError> {
        let mut iter = self.ix.outputs.iter();
        let Some(first) = iter.next() else {
            return Ok([0u8; 32]);
        };
        let mut acc = *first.utxo_hash;
        for output in iter {
            acc = poseidon2(&acc, output.utxo_hash)?;
        }
        Ok(acc)
    }
}

fn amount_field(amount: i128) -> Result<[u8; 32], ProgramError> {
    let magnitude = u64::try_from(amount.unsigned_abs())
        .map_err(|_| ShieldedPoolError::PublicAssetAmountOverflow)?;
    let value = Fr::from(magnitude);
    let limbs = if amount.is_negative() {
        (-value).into_bigint().0
    } else {
        value.into_bigint().0
    };
    let mut out = [0u8; 32];
    for (target, limb) in out.chunks_exact_mut(8).rev().zip(limbs.iter()) {
        target.copy_from_slice(&limb.to_be_bytes());
    }
    Ok(out)
}

const PROOF_ERR: ShieldedPoolError = ShieldedPoolError::TransactProofVerificationFailed;

fn poseidon2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    verifier::poseidon2(a, b, PROOF_ERR)
}

fn sha256(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    Sha256::hash(value).map_err(|_| PROOF_ERR.into())
}

fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    verifier::hash_field(value, PROOF_ERR)
}

fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], ProgramError> {
    verifier::hash_chain(items, PROOF_ERR)
}

/// Default `transact` (`IS_ZONE = false`): the recipient-binding confidential
/// keys. The instruction can only ever reach these, never the anonymous keys.
fn select_confidential_verifying_key<const IS_P256: bool>(
    n_inputs: usize,
    n_outputs: usize,
) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
    let key = match (n_inputs, n_outputs, IS_P256) {
        (1, 1, false) => &transfer_confidential_1_1::VERIFYINGKEY,
        (1, 1, true) => &transfer_p256_confidential_1_1::VERIFYINGKEY,
        (1, 2, false) => &transfer_confidential_1_2::VERIFYINGKEY,
        (1, 2, true) => &transfer_p256_confidential_1_2::VERIFYINGKEY,
        (2, 2, false) => &transfer_confidential_2_2::VERIFYINGKEY,
        (2, 2, true) => &transfer_p256_confidential_2_2::VERIFYINGKEY,
        (2, 3, false) => &transfer_confidential_2_3::VERIFYINGKEY,
        (2, 3, true) => &transfer_p256_confidential_2_3::VERIFYINGKEY,
        (3, 3, false) => &transfer_confidential_3_3::VERIFYINGKEY,
        (3, 3, true) => &transfer_p256_confidential_3_3::VERIFYINGKEY,
        (4, 3, false) => &transfer_confidential_4_3::VERIFYINGKEY,
        (4, 3, true) => &transfer_p256_confidential_4_3::VERIFYINGKEY,
        (4, 4, false) => &transfer_confidential_4_4::VERIFYINGKEY,
        (4, 4, true) => &transfer_p256_confidential_4_4::VERIFYINGKEY,
        (5, 3, false) => &transfer_confidential_5_3::VERIFYINGKEY,
        (5, 3, true) => &transfer_p256_confidential_5_3::VERIFYINGKEY,
        (5, 4, false) => &transfer_confidential_5_4::VERIFYINGKEY,
        (5, 4, true) => &transfer_p256_confidential_5_4::VERIFYINGKEY,
        (1, 8, false) => &transfer_confidential_1_8::VERIFYINGKEY,
        (1, 8, true) => &transfer_p256_confidential_1_8::VERIFYINGKEY,
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    };
    Ok(key)
}

/// `zone_transact` (`IS_ZONE = true`): the anonymous policy-zone keys (output
/// owners left free for view tags). Only the zone path resolves these.
fn select_zone_verifying_key<const IS_P256: bool>(
    n_inputs: usize,
    n_outputs: usize,
) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
    let key = match (n_inputs, n_outputs, IS_P256) {
        (1, 1, false) => &transfer_zone_1_1::VERIFYINGKEY,
        (1, 1, true) => &transfer_p256_zone_1_1::VERIFYINGKEY,
        (1, 2, false) => &transfer_zone_1_2::VERIFYINGKEY,
        (1, 2, true) => &transfer_p256_zone_1_2::VERIFYINGKEY,
        (2, 2, false) => &transfer_zone_2_2::VERIFYINGKEY,
        (2, 2, true) => &transfer_p256_zone_2_2::VERIFYINGKEY,
        (2, 3, false) => &transfer_zone_2_3::VERIFYINGKEY,
        (2, 3, true) => &transfer_p256_zone_2_3::VERIFYINGKEY,
        (3, 3, false) => &transfer_zone_3_3::VERIFYINGKEY,
        (3, 3, true) => &transfer_p256_zone_3_3::VERIFYINGKEY,
        (4, 3, false) => &transfer_zone_4_3::VERIFYINGKEY,
        (4, 3, true) => &transfer_p256_zone_4_3::VERIFYINGKEY,
        (4, 4, false) => &transfer_zone_4_4::VERIFYINGKEY,
        (4, 4, true) => &transfer_p256_zone_4_4::VERIFYINGKEY,
        (5, 3, false) => &transfer_zone_5_3::VERIFYINGKEY,
        (5, 3, true) => &transfer_p256_zone_5_3::VERIFYINGKEY,
        (5, 4, false) => &transfer_zone_5_4::VERIFYINGKEY,
        (5, 4, true) => &transfer_p256_zone_5_4::VERIFYINGKEY,
        (1, 8, false) => &transfer_zone_1_8::VERIFYINGKEY,
        (1, 8, true) => &transfer_p256_zone_1_8::VERIFYINGKEY,
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    };
    Ok(key)
}

/// `zone_authority_transact`: the zone-authority instantiation (anonymous owner
/// tag, no per-owner spend signature). It is a single vanilla-Groth16 key per
/// shape -- no P256/Solana rail split, since it recomputes each owner `pk_field`
/// from the witnessed point rather than verifying a signature. Shapes 1_1, 2_2,
/// 3_3, 4_4.
fn select_zone_authority_verifying_key(
    n_inputs: usize,
    n_outputs: usize,
) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
    let key = match (n_inputs, n_outputs) {
        (1, 1) => &transfer_zone_authority_1_1::VERIFYINGKEY,
        (2, 2) => &transfer_zone_authority_2_2::VERIFYINGKEY,
        (3, 3) => &transfer_zone_authority_3_3::VERIFYINGKEY,
        (4, 4) => &transfer_zone_authority_4_4::VERIFYINGKEY,
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    };
    Ok(key)
}

#[cfg(test)]
mod tests {
    use zolana_interface::instruction::instruction_data::transact::{CircuitId, TransactIxData};

    use super::*;

    fn check_selector_for<const IS_ZONE: bool, const IS_AUTHORITY: bool>(
        circuit: CircuitId,
        p256_signing_pk_x: Option<[u8; 32]>,
    ) -> ProgramResult {
        let ix = TransactIxData {
            proof: ProofData::zeroed_eddsa(),
            expiry_unix_ts: 0,
            private_tx_hash: [0u8; 32],
            circuit,
            p256_signing_pk_x,
            inputs: Vec::new(),
            public_legs: Vec::new(),
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            outputs: Vec::new(),
            messages: Vec::new(),
        };
        let bytes = ix.serialize().unwrap();
        let ix_ref = TransactIxDataRef::from_bytes(&bytes).unwrap();
        let derived = TransactProofInputs::default();
        TransactProof::new(&ix_ref, &derived).check_selector::<IS_ZONE, IS_AUTHORITY>()
    }

    /// The selector's type must match the dispatched instruction and its
    /// variant must match `p256_signing_pk_x` presence, on all three
    /// instruction paths.
    #[test]
    fn selector_type_and_variant_are_validated() {
        use CircuitId::*;
        use ShieldedPoolError::*;

        type Case = (
            (bool, bool),
            CircuitId,
            Option<[u8; 32]>,
            Result<(), ShieldedPoolError>,
        );
        let table: &[Case] = &[
            // transact: confidential only.
            ((false, false), ConfidentialEddsa, None, Ok(())),
            ((false, false), ConfidentialP256, Some([1u8; 32]), Ok(())),
            ((false, false), ZoneEddsa, None, Err(MismatchedCircuitType)),
            (
                (false, false),
                ZoneAuthority,
                None,
                Err(MismatchedCircuitType),
            ),
            (
                (false, false),
                ConfidentialP256,
                None,
                Err(MismatchedCircuitVariant),
            ),
            (
                (false, false),
                ConfidentialEddsa,
                Some([1u8; 32]),
                Err(MismatchedCircuitVariant),
            ),
            // zone_transact: zone only.
            ((true, false), ZoneEddsa, None, Ok(())),
            ((true, false), ZoneP256, Some([1u8; 32]), Ok(())),
            (
                (true, false),
                ConfidentialEddsa,
                None,
                Err(MismatchedCircuitType),
            ),
            (
                (true, false),
                ZoneAuthority,
                None,
                Err(MismatchedCircuitType),
            ),
            // zone_authority_transact: the single authority instantiation.
            ((true, true), ZoneAuthority, None, Ok(())),
            ((true, true), ZoneEddsa, None, Err(MismatchedCircuitType)),
            (
                (true, true),
                ZoneAuthority,
                Some([1u8; 32]),
                Err(MismatchedCircuitVariant),
            ),
        ];
        for &((is_zone, is_authority), circuit, p256_signing_pk_x, want) in table {
            let got = match (is_zone, is_authority) {
                (false, false) => check_selector_for::<false, false>(circuit, p256_signing_pk_x),
                (true, false) => check_selector_for::<true, false>(circuit, p256_signing_pk_x),
                (true, true) => check_selector_for::<true, true>(circuit, p256_signing_pk_x),
                (false, true) => unreachable!("no such instruction"),
            };
            let want = want.map_err(ProgramError::from);
            assert_eq!(got, want, "circuit {circuit:?}");
        }
    }

    /// Every supported shape resolves a verifying key on all four
    /// rail/zone combinations, and the four are distinct keys per shape.
    #[test]
    fn select_verifying_key_covers_zone_and_confidential() {
        let shapes = [
            (1, 1),
            (1, 2),
            (2, 2),
            (2, 3),
            (3, 3),
            (4, 3),
            (4, 4),
            (5, 3),
            (5, 4),
            (1, 8),
        ];
        for (n_in, n_out) in shapes {
            let conf_eddsa = select_confidential_verifying_key::<false>(n_in, n_out).unwrap();
            let conf_p256 = select_confidential_verifying_key::<true>(n_in, n_out).unwrap();
            let zone_eddsa = select_zone_verifying_key::<false>(n_in, n_out).unwrap();
            let zone_p256 = select_zone_verifying_key::<true>(n_in, n_out).unwrap();
            // The zone (anonymous) keys must differ from the confidential keys and
            // from each other, so a zone proof can never verify against a
            // confidential key (or the wrong rail).
            assert!(!core::ptr::eq(conf_eddsa, zone_eddsa));
            assert!(!core::ptr::eq(conf_p256, zone_p256));
            assert!(!core::ptr::eq(zone_eddsa, zone_p256));
        }
    }

    #[test]
    fn select_verifying_key_rejects_unsupported_shape() {
        assert!(select_confidential_verifying_key::<false>(6, 6).is_err());
        assert!(select_zone_verifying_key::<true>(6, 6).is_err());
    }
}
