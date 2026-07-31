use ark_bn254::Fr;
use ark_ff::PrimeField;
use arrayvec::ArrayVec as RefArrayVec;
use light_array_map::ArrayMap;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use tinyvec::ArrayVec;
use zolana_hasher::{
    hash_chain::{create_hash_chain_from_slice, create_hash_chain_from_slice_ref},
    primitives::hash_bytes,
    sha256::Sha256,
    Hasher, Poseidon,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{
        is_confidential_encrypted_output, CircuitId, InterfaceTransfer, ResolvedOutput,
        TransactIxDataRef,
    },
    verifying_keys::OutputOwnerMode,
    N_PUBLIC_SLOTS, SOL_ASSET_FIELD,
};

use crate::instructions::{settlement::Settlement, verifier};

pub const MAX_INPUTS: usize = 5;

pub const MAX_SIGNERS: usize = MAX_INPUTS + 1;

pub const MAX_OUTPUTS: usize = 8;

const MAX_OWNER_HASHES: usize = MAX_SIGNERS + MAX_OUTPUTS;

pub(crate) type OwnerHashCache = ArrayMap<[u8; 32], [u8; 32], MAX_OWNER_HASHES>;

const ASSIGNED_OUTPUT_OWNERS: u8 = 1 << 0;
const ASSIGNED_OWNER_SIGNERS: u8 = 1 << 1;
const ASSIGNED_PUBLIC_TRANSFERS: u8 = 1 << 2;
const ASSIGNED_INPUT_TREE: u8 = 1 << 3;
const ASSIGNED_EXTERNAL_DATA: u8 = 1 << 4;
const ASSIGNED_ZONE_PROGRAM: u8 = 1 << 5;
const ALL_ASSIGNMENTS: u8 = ASSIGNED_OUTPUT_OWNERS
    | ASSIGNED_OWNER_SIGNERS
    | ASSIGNED_PUBLIC_TRANSFERS
    | ASSIGNED_INPUT_TREE
    | ASSIGNED_EXTERNAL_DATA
    | ASSIGNED_ZONE_PROGRAM;

#[derive(Debug)]
pub struct TransactProofInputs {
    pub(crate) utxo_roots: [[u8; 32]; MAX_INPUTS],
    pub(crate) nullifier_tree_roots: [[u8; 32]; MAX_INPUTS],
    pub(crate) signer_pk_hashes: [[u8; 32]; MAX_SIGNERS],
    pub(crate) output_owner_pk_hashes: [[u8; 32]; MAX_OUTPUTS],
    pub(crate) external_data_hash: [u8; 32],
    pub(crate) public_slot_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub(crate) public_slot_amounts: [i128; N_PUBLIC_SLOTS],
    pub(crate) zone_program_id: [u8; 32],
    pub(crate) allow_dummy_inputs: [u8; 32],
    unique_owner_signer_count: u8,
    assignments: u8,
}

impl TransactProofInputs {
    pub(crate) fn new(circuit: CircuitId) -> Self {
        let mut assignments = 0;
        if matches!(circuit, CircuitId::ConfidentialEddsa(..)) {
            assignments |= ASSIGNED_ZONE_PROGRAM;
        }
        Self {
            utxo_roots: [[0u8; 32]; MAX_INPUTS],
            nullifier_tree_roots: [[0u8; 32]; MAX_INPUTS],
            signer_pk_hashes: [[0u8; 32]; MAX_SIGNERS],
            output_owner_pk_hashes: [[0u8; 32]; MAX_OUTPUTS],
            external_data_hash: [0u8; 32],
            public_slot_assets: [[0u8; 32]; N_PUBLIC_SLOTS],
            public_slot_amounts: [0i128; N_PUBLIC_SLOTS],
            zone_program_id: [0u8; 32],
            allow_dummy_inputs: [0u8; 32],
            unique_owner_signer_count: 0,
            assignments,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_tests() -> Self {
        Self::new(CircuitId::ConfidentialEddsa(1, 1, 1))
    }

    pub(crate) fn assign_zone_program_id(&mut self, zone_program_id: [u8; 32]) {
        self.zone_program_id = zone_program_id;
        self.assignments |= ASSIGNED_ZONE_PROGRAM;
    }

    pub(crate) fn assign_input_tree(
        &mut self,
        utxo_roots: &[[u8; 32]],
        nullifier_tree_roots: &[[u8; 32]],
        allow_dummy_inputs: [u8; 32],
    ) -> Result<(), ProgramError> {
        if utxo_roots.len() != nullifier_tree_roots.len() || utxo_roots.len() > MAX_INPUTS {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }
        self.utxo_roots[..utxo_roots.len()].copy_from_slice(utxo_roots);
        self.nullifier_tree_roots[..nullifier_tree_roots.len()]
            .copy_from_slice(nullifier_tree_roots);
        self.allow_dummy_inputs = allow_dummy_inputs;
        self.assignments |= ASSIGNED_INPUT_TREE;
        Ok(())
    }

    pub(crate) fn assign_external_data_hash(&mut self, external_data_hash: [u8; 32]) {
        self.external_data_hash = external_data_hash;
        self.assignments |= ASSIGNED_EXTERNAL_DATA;
    }

    pub(crate) fn ensure_complete(&self) -> Result<(), ProgramError> {
        if self.assignments != ALL_ASSIGNMENTS {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }
        Ok(())
    }

    // Assign the payer and ordered, first-occurrence-deduplicated EdDSA signer
    // identities. The payer occupies slot zero and seeds `seen`, so an appended
    // payer is ignored.
    #[profile]
    pub(crate) fn fill_owner_signer_hashes(
        &mut self,
        payer: &AccountView,
        owner_signers: &[AccountView],
        owner_hashes: &mut OwnerHashCache,
    ) -> Result<(), ProgramError> {
        let payer_address = payer.address().to_bytes();
        self.signer_pk_hashes[0] = cached_owner_hash(owner_hashes, &payer_address)?;

        let mut seen: ArrayMap<[u8; 32], (), MAX_SIGNERS> = ArrayMap::new();
        seen.insert(payer_address, (), ShieldedPoolError::InvalidTransactShape)?;
        let mut unique_count = 1usize;
        for signer in owner_signers {
            let address = signer.address().to_bytes();
            if seen.get_by_pubkey(&address).is_some() {
                continue;
            }
            seen.insert(address, (), ShieldedPoolError::InvalidTransactShape)?;
            *self
                .signer_pk_hashes
                .get_mut(unique_count)
                .ok_or(ShieldedPoolError::InvalidTransactShape)? =
                cached_owner_hash(owner_hashes, &address)?;
            unique_count += 1;
        }
        self.unique_owner_signer_count =
            u8::try_from(unique_count).map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
        self.assignments |= ASSIGNED_OWNER_SIGNERS;
        Ok(())
    }

    #[profile]
    pub(crate) fn fill_output_owner_pk_hashes(
        &mut self,
        mode: OutputOwnerMode,
        resolved_outputs: &[ResolvedOutput],
        owner_hashes: &mut OwnerHashCache,
    ) -> Result<(), ProgramError> {
        if resolved_outputs.len() > MAX_OUTPUTS {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }
        match mode {
            OutputOwnerMode::None => {}
            OutputOwnerMode::All => {
                for (index, output) in resolved_outputs.iter().enumerate() {
                    self.output_owner_pk_hashes[index] =
                        cached_owner_hash(owner_hashes, &output.owner_tag)?;
                }
            }
            OutputOwnerMode::ConfidentialMarked => {
                for (index, output) in resolved_outputs.iter().enumerate() {
                    if output.data.is_some_and(is_confidential_encrypted_output) {
                        self.output_owner_pk_hashes[index] =
                            cached_owner_hash(owner_hashes, &output.owner_tag)?;
                    }
                }
            }
        }
        self.assignments |= ASSIGNED_OUTPUT_OWNERS;
        Ok(())
    }

    pub(crate) fn assign_public_amounts_and_assets(
        &mut self,
        interface_transfers: &[InterfaceTransfer],
        settlements: &[Settlement<'_>],
        num_public_asset_slots: usize,
    ) -> Result<(), ProgramError> {
        if interface_transfers.len() != settlements.len() || num_public_asset_slots > N_PUBLIC_SLOTS
        {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }

        let mut used_slots = 0usize;
        for (transfer, settlement) in interface_transfers.iter().zip(settlements.iter()) {
            let amount = signed_amount(*transfer);
            if amount == 0 || transfer.is_deposit() != settlement.is_deposit() {
                return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
            }

            let hashed_mint = match settlement.spl_asset()? {
                Some(mint) => hash_bytes(&mint)?,
                None => SOL_ASSET_FIELD,
            };
            match self.public_slot_assets[..used_slots]
                .iter()
                .position(|slot_asset| *slot_asset == hashed_mint)
            {
                Some(index) => {
                    let net = self.public_slot_amounts[index]
                        .checked_add(amount)
                        .ok_or(ShieldedPoolError::PublicAssetAmountOverflow)?;
                    self.public_slot_amounts[index] = checked_slot_amount(net)?;
                }
                None => {
                    if used_slots == num_public_asset_slots {
                        return Err(ShieldedPoolError::TooManyPublicAssets.into());
                    }
                    self.public_slot_assets[used_slots] = hashed_mint;
                    self.public_slot_amounts[used_slots] = checked_slot_amount(amount)?;
                    used_slots += 1;
                }
            }
        }
        if self.public_slot_amounts[..used_slots].contains(&0) {
            return Err(ShieldedPoolError::ZeroNetInterfaceTransferAmount.into());
        }
        self.assignments |= ASSIGNED_PUBLIC_TRANSFERS;
        Ok(())
    }
}

fn cached_owner_hash(
    owner_hashes: &mut OwnerHashCache,
    owner_tag: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    if let Some(hash) = owner_hashes.get_by_pubkey(owner_tag) {
        return Ok(*hash);
    }
    let hash = hash_bytes(owner_tag)?;
    owner_hashes.insert(
        *owner_tag,
        hash,
        ProgramError::from(ShieldedPoolError::InvalidTransactShape),
    )?;
    Ok(hash)
}

fn checked_slot_amount(net: i128) -> Result<i128, ProgramError> {
    if u64::try_from(net.unsigned_abs()).is_err() {
        return Err(ShieldedPoolError::PublicAssetAmountOverflow.into());
    }
    Ok(net)
}

fn signed_amount(transfer: InterfaceTransfer) -> i128 {
    let amount = i128::from(transfer.amount());
    if transfer.is_deposit() {
        amount
    } else {
        -amount
    }
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

    /// The processor validates the selector against the dispatched instruction
    /// before account parsing. The validated selector is then the source of truth
    /// for the public-input layout and verifying key.
    #[inline(never)]
    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let verifying_key = self
            .ix
            .circuit
            .verifying_key()
            .ok_or(ShieldedPoolError::InvalidTransactShape)?;
        let encoding_err = ShieldedPoolError::InvalidTransactProofEncoding;
        let verify_err = ShieldedPoolError::TransactProofVerificationFailed;
        let proof_data = &self.ix.proof;
        let commitment = self
            .ix
            .circuit
            .bsb22_commitment()
            .map(|value| (&value.commitment, &value.commitment_pok));
        let proof = verifier::CompressedGroth16Proof {
            a: &proof_data.a,
            b: &proof_data.b,
            c: &proof_data.c,
            commitment,
        };
        verifier::verify_groth16(
            proof,
            public_input_hash,
            verifying_key,
            encoding_err,
            verify_err,
        )
    }

    fn n_inputs(&self) -> usize {
        usize::from(self.ix.circuit.num_inputs())
    }

    fn n_outputs(&self) -> usize {
        usize::from(self.ix.circuit.num_outputs())
    }

    fn n_public_asset_slots(&self) -> usize {
        usize::from(self.ix.circuit.num_public_asset_slots())
    }

    #[inline(never)]
    fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        let n_in = self.n_inputs();
        let n_out = self.n_outputs();
        let n_public_asset_slots = self.n_public_asset_slots();
        let shape = ShieldedPoolError::InvalidTransactShape;
        let utxo_roots = self.derived.utxo_roots.get(..n_in).ok_or(shape)?;
        let nullifier_tree_roots = self.derived.nullifier_tree_roots.get(..n_in).ok_or(shape)?;
        let signer_width = if self.ix.circuit.requires_input_signatures() {
            n_in.checked_add(1).ok_or(shape)?
        } else {
            1
        };
        let signer_pk_hashes = self
            .derived
            .signer_pk_hashes
            .get(..signer_width)
            .ok_or(shape)?;
        let unique_signer_pk_hashes = signer_pk_hashes
            .get(..usize::from(self.derived.unique_owner_signer_count))
            .ok_or(shape)?;
        let output_owner_pk_hashes = self
            .derived
            .output_owner_pk_hashes
            .get(..n_out)
            .ok_or(shape)?;
        let public_slot_assets = self
            .derived
            .public_slot_assets
            .get(..n_public_asset_slots)
            .ok_or(shape)?;
        let public_slot_amounts = self
            .derived
            .public_slot_amounts
            .get(..n_public_asset_slots)
            .ok_or(shape)?;

        let nullifier_chain = {
            let mut nullifiers: RefArrayVec<&[u8; 32], MAX_INPUTS> = RefArrayVec::new();
            for input in &self.ix.inputs {
                nullifiers
                    .try_push(&input.nullifier_hash)
                    .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
            }
            create_hash_chain_from_slice_ref(nullifiers.as_slice())?
        };
        let output_chain = {
            let mut utxo_hashes: RefArrayVec<&[u8; 32], MAX_OUTPUTS> = RefArrayVec::new();
            for output in &self.ix.outputs {
                utxo_hashes
                    .try_push(output.utxo_hash)
                    .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
            }
            create_hash_chain_from_slice_ref(utxo_hashes.as_slice())?
        };
        let mut fields: ArrayVec<[[u8; 32]; 20]> = ArrayVec::new();
        fields.extend_from_slice(&[
            nullifier_chain,
            output_chain,
            create_hash_chain_from_slice(utxo_roots)?,
            create_hash_chain_from_slice(nullifier_tree_roots)?,
            *self.ix.private_tx_hash,
        ]);
        if self.ix.circuit.is_p256() {
            let message_digest = Sha256::hash(self.ix.private_tx_hash)
                .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
            fields.push(hash_bytes(&message_digest)?);
            fields.push(match self.ix.circuit.default_p256_owner_tag() {
                Some(owner_tag) => hash_bytes(owner_tag)?,
                None => [0u8; 32],
            });
        }
        fields.push(self.derived.external_data_hash);
        for (asset, amount) in public_slot_assets.iter().zip(public_slot_amounts.iter()) {
            fields.push(*asset);
            fields.push(amount_field(*amount)?);
        }
        fields.extend_from_slice(&[
            self.derived.zone_program_id,
            fixed_signer_hash_chain(unique_signer_pk_hashes, signer_width)?,
            self.derived.allow_dummy_inputs,
        ]);
        if self.ix.circuit.output_owner_mode() != OutputOwnerMode::None {
            fields.push(create_hash_chain_from_slice(output_owner_pk_hashes)?);
        }
        create_hash_chain_from_slice(fields.as_slice()).map_err(Into::into)
    }
}

// All-zero right-fold suffixes Z1..Z6, where Z1 = 0 and
// Z(k) = Poseidon(0, Z(k-1)). These let the program hash only the populated
// unique signer prefix while matching the circuit's fixed-width right-fold.
const SIGNER_ZERO_SUFFIX_CHAINS: [[u8; 32]; MAX_SIGNERS] = [
    [0u8; 32],
    [
        0x20, 0x98, 0xf5, 0xfb, 0x9e, 0x23, 0x9e, 0xab, 0x3c, 0xea, 0xc3, 0xf2, 0x7b, 0x81, 0xe4,
        0x81, 0xdc, 0x31, 0x24, 0xd5, 0x5f, 0xfe, 0xd5, 0x23, 0xa8, 0x39, 0xee, 0x84, 0x46, 0xb6,
        0x48, 0x64,
    ],
    [
        0x15, 0x30, 0x57, 0x2d, 0x8f, 0xaf, 0x83, 0xd4, 0x7b, 0xb6, 0x40, 0x0a, 0x96, 0x23, 0x7d,
        0x6e, 0x9d, 0x1d, 0xb8, 0xf3, 0xef, 0x40, 0xe8, 0x67, 0x08, 0x88, 0xfb, 0x9d, 0x65, 0x38,
        0x0a, 0xc8,
    ],
    [
        0x01, 0xcb, 0xcc, 0x84, 0x29, 0x70, 0xc5, 0xb0, 0x5d, 0x88, 0x1e, 0x0f, 0x17, 0x18, 0x22,
        0xa7, 0x08, 0x8c, 0xa3, 0xd1, 0x1e, 0xfd, 0x0a, 0xac, 0x74, 0x5e, 0xe0, 0x13, 0x03, 0xe1,
        0x3e, 0xe8,
    ],
    [
        0x23, 0x5f, 0x18, 0x00, 0x6f, 0xbf, 0x4e, 0xfc, 0xc6, 0xfd, 0xf3, 0xc3, 0x2c, 0x8c, 0x5e,
        0x91, 0x3d, 0x24, 0x88, 0xce, 0x1a, 0x06, 0xd9, 0x86, 0xe9, 0x19, 0x1c, 0xc9, 0xb0, 0x65,
        0x39, 0xa7,
    ],
    [
        0x2b, 0xd8, 0x9a, 0x7b, 0x00, 0xc5, 0x08, 0x18, 0x12, 0xf1, 0xdd, 0xaf, 0x86, 0x33, 0x1f,
        0x32, 0x60, 0x78, 0x7a, 0x32, 0x5c, 0x8a, 0xe3, 0xce, 0xd9, 0xe4, 0xc7, 0xee, 0x3f, 0xb5,
        0x9b, 0x6b,
    ],
];

fn fixed_signer_hash_chain(
    unique_signer_pk_hashes: &[[u8; 32]],
    width: usize,
) -> Result<[u8; 32], ProgramError> {
    let unique_count = unique_signer_pk_hashes.len();
    if unique_count == 0 || width > MAX_SIGNERS || unique_count > width {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    let mut index = unique_count;
    let mut chain = if unique_count == width {
        index -= 1;
        unique_signer_pk_hashes[index]
    } else {
        SIGNER_ZERO_SUFFIX_CHAINS[width - unique_count - 1]
    };
    while index > 0 {
        index -= 1;
        chain = Poseidon::hashv(&[&unique_signer_pk_hashes[index], &chain])
            .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
    }
    Ok(chain)
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

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_account_checks::account_info::test_account_info::get_account_view;
    use zolana_hasher::hash_chain::create_right_hash_chain_from_slice;

    #[test]
    fn incomplete_proof_inputs_are_rejected() {
        let proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));

        assert_eq!(
            proof_inputs.ensure_complete(),
            Err(ProgramError::Custom(
                ShieldedPoolError::InvalidTransactShape as u32
            ))
        );
    }

    #[test]
    fn owner_signers_are_first_occurrence_deduplicated_with_payer_first() {
        let payer = get_account_view([1; 32], [0; 32], true, false, false, vec![]);
        let owner_signers = vec![
            get_account_view([2; 32], [0; 32], true, false, false, vec![]),
            get_account_view([1; 32], [0; 32], true, false, false, vec![]),
            get_account_view([2; 32], [0; 32], true, false, false, vec![]),
            get_account_view([3; 32], [0; 32], true, false, false, vec![]),
        ];
        let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 1, 1));
        let mut owner_hashes = OwnerHashCache::new();

        proof_inputs
            .fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes)
            .unwrap();

        assert_eq!(proof_inputs.unique_owner_signer_count, 3);
        assert_eq!(
            proof_inputs.signer_pk_hashes[0],
            hash_bytes(&[1; 32]).unwrap()
        );
        assert_eq!(
            proof_inputs.signer_pk_hashes[1],
            hash_bytes(&[2; 32]).unwrap()
        );
        assert_eq!(
            proof_inputs.signer_pk_hashes[2],
            hash_bytes(&[3; 32]).unwrap()
        );
        assert_eq!(proof_inputs.signer_pk_hashes[3], [0; 32]);
    }

    #[test]
    fn owner_hashes_are_reused_between_outputs_and_signers() {
        let utxo_hashes = [[0u8; 32]; 3];
        let outputs = [
            ResolvedOutput {
                utxo_hash: &utxo_hashes[0],
                owner_tag: [1; 32],
                data: None,
            },
            ResolvedOutput {
                utxo_hash: &utxo_hashes[1],
                owner_tag: [2; 32],
                data: None,
            },
            ResolvedOutput {
                utxo_hash: &utxo_hashes[2],
                owner_tag: [1; 32],
                data: None,
            },
        ];
        let payer = get_account_view([1; 32], [0; 32], true, false, false, vec![]);
        let owner_signers = [get_account_view(
            [3; 32],
            [0; 32],
            true,
            false,
            false,
            vec![],
        )];
        let mut proof_inputs = TransactProofInputs::new(CircuitId::ConfidentialEddsa(1, 3, 1));
        let mut owner_hashes = OwnerHashCache::new();

        proof_inputs
            .fill_output_owner_pk_hashes(OutputOwnerMode::All, &outputs, &mut owner_hashes)
            .unwrap();
        assert_eq!(owner_hashes.len(), 2);

        proof_inputs
            .fill_owner_signer_hashes(&payer, &owner_signers, &mut owner_hashes)
            .unwrap();
        assert_eq!(owner_hashes.len(), 3);
        assert_eq!(
            proof_inputs.output_owner_pk_hashes[0],
            proof_inputs.signer_pk_hashes[0]
        );
        assert_eq!(
            proof_inputs.output_owner_pk_hashes[0],
            proof_inputs.output_owner_pk_hashes[2]
        );
    }

    #[test]
    fn confidential_marked_mode_hashes_only_marked_output_tags() {
        let utxo_hashes = [[0u8; 32]; 3];
        let confidential = [1, 2, 0, 0, 0, 3, 9];
        let anonymous = [1, 2, 0, 0, 0, 2, 9];
        let malformed_length = [1, 3, 0, 0, 0, 3, 9];
        let outputs = [
            ResolvedOutput {
                utxo_hash: &utxo_hashes[0],
                owner_tag: [1; 32],
                data: Some(&confidential),
            },
            ResolvedOutput {
                utxo_hash: &utxo_hashes[1],
                owner_tag: [2; 32],
                data: Some(&anonymous),
            },
            ResolvedOutput {
                utxo_hash: &utxo_hashes[2],
                owner_tag: [3; 32],
                data: Some(&malformed_length),
            },
        ];
        let mut proof_inputs = TransactProofInputs::new(CircuitId::ZoneEddsa(1, 3, 1));
        let mut owner_hashes = OwnerHashCache::new();

        proof_inputs
            .fill_output_owner_pk_hashes(
                OutputOwnerMode::ConfidentialMarked,
                &outputs,
                &mut owner_hashes,
            )
            .unwrap();

        assert_eq!(
            proof_inputs.output_owner_pk_hashes[0],
            hash_bytes(&[1; 32]).unwrap()
        );
        assert_eq!(proof_inputs.output_owner_pk_hashes[1], [0; 32]);
        assert_eq!(proof_inputs.output_owner_pk_hashes[2], [0; 32]);
        assert_eq!(owner_hashes.len(), 1);
    }

    #[test]
    fn zero_suffix_optimization_matches_fixed_width_right_fold() {
        for width in 1..=MAX_SIGNERS {
            for unique_count in 1..=width {
                let mut signers = vec![[0u8; 32]; width];
                for (index, signer) in signers.iter_mut().take(unique_count).enumerate() {
                    signer[31] = (index + 1) as u8;
                }
                assert_eq!(
                    fixed_signer_hash_chain(&signers[..unique_count], width).unwrap(),
                    create_right_hash_chain_from_slice(&signers).unwrap(),
                    "width={width}, unique_count={unique_count}",
                );
            }
        }
    }

    #[test]
    fn zero_suffix_constants_cover_every_supported_width() {
        for width in 1..=MAX_SIGNERS {
            let zeros = vec![[0u8; 32]; width];
            assert_eq!(
                SIGNER_ZERO_SUFFIX_CHAINS[width - 1],
                create_right_hash_chain_from_slice(&zeros).unwrap(),
            );
        }
    }

    #[test]
    fn fixed_signer_hash_chain_rejects_empty_signer_prefix() {
        assert_eq!(
            fixed_signer_hash_chain(&[], 1),
            Err(ProgramError::Custom(
                ShieldedPoolError::InvalidTransactShape as u32
            )),
        );
    }
}
