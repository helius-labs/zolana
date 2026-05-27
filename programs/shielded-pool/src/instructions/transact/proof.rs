use light_hasher::{
    hash_to_field_size::hashv_to_bn254_field_size_be_const_array, Hasher, Poseidon,
};
use light_verifier::CompressedProof;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_interface::instruction::{
    TransactData, PUBLIC_AMOUNT_DEPOSIT, PUBLIC_AMOUNT_NONE, PUBLIC_AMOUNT_WITHDRAW,
};

use super::settlement::SettlementAccounts;
use super::verifying_key;
use crate::{
    error::ShieldedPoolError, instructions::create_pool_tree::init::current_state_root, log::log,
};

const SPP_INPUTS: usize = 1;
const SPP_OUTPUTS: usize = 2;
const COMPRESSED_PROOF_SIZE: usize = 128;
const EMPTY_FIELD: [u8; 32] = [0u8; 32];
const INITIAL_NULLIFIER_ROOT: [u8; 32] = [
    0x1d, 0x8e, 0x71, 0xa6, 0x01, 0xb3, 0xe8, 0xde, 0xbb, 0xba, 0x9b, 0x55, 0x7b, 0x83, 0x69, 0xc7,
    0xf4, 0x04, 0xae, 0x57, 0xbe, 0xbf, 0x08, 0x52, 0x23, 0x6b, 0x07, 0x28, 0x20, 0x95, 0x42, 0x77,
];
const BN254_FR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

pub fn verify_transact_proof(
    pool_tree_bytes: &[u8],
    data: &TransactData,
    settlement: &SettlementAccounts<'_>,
) -> ProgramResult {
    let public_input_hash = public_input_hash(pool_tree_bytes, data, settlement)?;
    let compressed_proof = compressed_proof(&data.proof)?;

    light_verifier::verify::<1>(
        &[public_input_hash],
        &compressed_proof,
        &verifying_key::VERIFYINGKEY,
    )
    .map_err(|_| {
        log("transact: SPP Groth16 verification failed");
        ProgramError::from(ShieldedPoolError::TransactProofVerificationFailed)
    })
}

fn public_input_hash(
    pool_tree_bytes: &[u8],
    data: &TransactData,
    settlement: &SettlementAccounts<'_>,
) -> Result<[u8; 32], ProgramError> {
    if data.nullifiers.len() > SPP_INPUTS || data.output_utxo_hashes.len() > SPP_OUTPUTS {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    let nullifiers = padded_values::<SPP_INPUTS>(&data.nullifiers);
    let output_utxo_hashes = padded_values::<SPP_OUTPUTS>(&data.output_utxo_hashes);
    let utxo_tree_roots = input_roots::<SPP_INPUTS>(pool_tree_bytes, data)?;
    let nullifier_roots = nullifier_roots::<SPP_INPUTS>(data)?;
    let external_data_hash = external_data_hash(data, settlement)?;
    let public_sol_amount = signed_public_sol_amount(data)?;
    let public_spl_amount = signed_public_amount(data.public_amount_mode, data.public_spl_amount)?;
    let public_spl_asset = if data.public_spl_amount.unwrap_or(0) == 0 {
        EMPTY_FIELD
    } else {
        field_from_u64(data.public_spl_asset_id)
    };

    hash_chain(&[
        hash_chain(&nullifiers)?,
        hash_chain(&output_utxo_hashes)?,
        hash_chain(&utxo_tree_roots)?,
        hash_chain(&nullifier_roots)?,
        data.private_tx_hash,
        external_data_hash,
        public_sol_amount,
        public_spl_amount,
        public_spl_asset,
        EMPTY_FIELD,
        signer_pubkey_hash(settlement)?,
        EMPTY_FIELD,
        EMPTY_FIELD,
    ])
}

fn compressed_proof(proof: &[u8; 192]) -> Result<CompressedProof, ProgramError> {
    if proof[COMPRESSED_PROOF_SIZE..].iter().any(|byte| *byte != 0) {
        log("transact: SPP proof has non-zero trailing bytes");
        return Err(ShieldedPoolError::InvalidTransactProofEncoding.into());
    }

    let mut a = [0u8; 32];
    a.copy_from_slice(&proof[..32]);
    let mut b = [0u8; 64];
    b.copy_from_slice(&proof[32..96]);
    let mut c = [0u8; 32];
    c.copy_from_slice(&proof[96..128]);
    Ok(CompressedProof { a, b, c })
}

fn input_roots<const N: usize>(
    pool_tree_bytes: &[u8],
    data: &TransactData,
) -> Result<[[u8; 32]; N], ProgramError> {
    let mut roots = [[0u8; 32]; N];
    if !data.nullifiers.is_empty() {
        let root = current_state_root(pool_tree_bytes)
            .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
        roots[..data.nullifiers.len()].fill(root);
    }
    Ok(roots)
}

fn nullifier_roots<const N: usize>(data: &TransactData) -> Result<[[u8; 32]; N], ProgramError> {
    let mut roots = [[0u8; 32]; N];
    roots[..data.nullifiers.len()].fill(INITIAL_NULLIFIER_ROOT);
    Ok(roots)
}

fn external_data_hash(
    data: &TransactData,
    settlement: &SettlementAccounts<'_>,
) -> Result<[u8; 32], ProgramError> {
    // TODO(v2): strengthen this v1 flat encoding with explicit direction and
    // length-delimited encrypted outputs before adding richer transaction
    // variants.
    let relayer_fee = data.relayer_fee.to_be_bytes();
    let public_sol_amount = data.public_sol_amount.unwrap_or(0).to_be_bytes();
    let public_spl_amount = data.public_spl_amount.unwrap_or(0).to_be_bytes();
    let user_sol_account = account_address_or_zero(settlement.user_sol_account);
    let user_spl_token_account = account_address_or_zero(settlement.user_spl_token_account);
    let spl_token_interface = account_address_or_zero(settlement.spl_vault);

    hashv_to_bn254_field_size_be_const_array::<9>(&[
        data.sender_view_tag.as_slice(),
        relayer_fee.as_slice(),
        public_sol_amount.as_slice(),
        public_spl_amount.as_slice(),
        user_sol_account.as_slice(),
        user_spl_token_account.as_slice(),
        spl_token_interface.as_slice(),
        data.encrypted_utxos.as_slice(),
    ])
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}

fn account_address_or_zero(account: Option<&AccountView>) -> [u8; 32] {
    let Some(account) = account else {
        return EMPTY_FIELD;
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(account.address().as_ref());
    out
}

fn signer_pubkey_hash(settlement: &SettlementAccounts<'_>) -> Result<[u8; 32], ProgramError> {
    hashv_to_bn254_field_size_be_const_array::<2>(&[settlement.signer.address().as_ref()])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}

fn signed_public_sol_amount(data: &TransactData) -> Result<[u8; 32], ProgramError> {
    let amount = data.public_sol_amount.unwrap_or(0);
    let fee = data.relayer_fee as u64;
    match data.public_amount_mode {
        PUBLIC_AMOUNT_NONE => {
            if amount != 0 || fee != 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            Ok(EMPTY_FIELD)
        }
        PUBLIC_AMOUNT_DEPOSIT => {
            if fee != 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            Ok(field_from_u64(amount))
        }
        PUBLIC_AMOUNT_WITHDRAW => {
            let amount = amount
                .checked_add(fee)
                .ok_or(ShieldedPoolError::InvalidTransactShape)?;
            Ok(negative_field_from_u64(amount))
        }
        _ => Err(ShieldedPoolError::InvalidTransactShape.into()),
    }
}

fn signed_public_amount(mode: u8, amount: Option<u64>) -> Result<[u8; 32], ProgramError> {
    let amount = amount.unwrap_or(0);
    match mode {
        PUBLIC_AMOUNT_NONE => {
            if amount != 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            Ok(EMPTY_FIELD)
        }
        PUBLIC_AMOUNT_DEPOSIT => Ok(field_from_u64(amount)),
        PUBLIC_AMOUNT_WITHDRAW => Ok(negative_field_from_u64(amount)),
        _ => Err(ShieldedPoolError::InvalidTransactShape.into()),
    }
}

fn hash_chain(values: &[[u8; 32]]) -> Result<[u8; 32], ProgramError> {
    if values.is_empty() {
        return Ok(EMPTY_FIELD);
    }

    let mut hash = values[values.len() - 1];
    for value in values[..values.len() - 1].iter().rev() {
        hash = Poseidon::hashv(&[value.as_slice(), hash.as_slice()])
            .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
    }
    Ok(hash)
}

fn padded_values<const N: usize>(values: &[[u8; 32]]) -> [[u8; 32]; N] {
    let mut out = [[0u8; 32]; N];
    out[..values.len()].copy_from_slice(values);
    out
}

fn field_from_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

fn negative_field_from_u64(value: u64) -> [u8; 32] {
    if value == 0 {
        return EMPTY_FIELD;
    }

    let mut out = BN254_FR_MODULUS;
    let value = value.to_be_bytes();
    let mut borrow = 0u16;
    for i in (0..8).rev() {
        let index = 24 + i;
        let lhs = out[index] as u16;
        let rhs = value[i] as u16 + borrow;
        if lhs >= rhs {
            out[index] = (lhs - rhs) as u8;
            borrow = 0;
        } else {
            out[index] = (lhs + 256 - rhs) as u8;
            borrow = 1;
        }
    }
    for byte in out[..24].iter_mut().rev() {
        if borrow == 0 {
            break;
        }
        if *byte == 0 {
            *byte = 255;
        } else {
            *byte -= 1;
            borrow = 0;
        }
    }
    out
}
