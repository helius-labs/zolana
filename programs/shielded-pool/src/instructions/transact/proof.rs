use groth16_solana_bsb22::{decompression, groth16::Groth16Verifier};
use light_hasher::{Hasher, Poseidon};
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use solana_sha256_hasher::hashv as sha256_hashv;
use zolana_interface::instruction::{
    tag, TransactData, PUBLIC_AMOUNT_DEPOSIT, PUBLIC_AMOUNT_NONE, PUBLIC_AMOUNT_WITHDRAW,
};

use super::settlement::{spl_asset_pubkey, SettlementAccounts};
use super::verifying_keys;
use crate::{
    error::ShieldedPoolError,
    instructions::create_pool_tree::init::{nullifier_root_by_index, state_root_by_index},
    log::log,
};

const SPP_MAX_INPUTS: usize = 5;
const SPP_MAX_OUTPUTS: usize = 8;
const EMPTY_FIELD: [u8; 32] = [0u8; 32];
const BN254_FR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

pub fn verify_transact_proof(
    pool_tree_bytes: &mut [u8],
    data: &TransactData,
    settlement: &SettlementAccounts<'_>,
) -> ProgramResult {
    let proof = bsb22_proof(&data.proof)?;

    match canonical_shape(data)? {
        (1, 2) => verify_shape::<1, 2>(
            pool_tree_bytes,
            data,
            settlement,
            &proof,
            &verifying_keys::spp_1_2::VERIFYINGKEY,
        ),
        (1, 8) => verify_shape::<1, 8>(
            pool_tree_bytes,
            data,
            settlement,
            &proof,
            &verifying_keys::spp_1_8::VERIFYINGKEY,
        ),
        (2, 2) => verify_shape::<2, 2>(
            pool_tree_bytes,
            data,
            settlement,
            &proof,
            &verifying_keys::spp_2_2::VERIFYINGKEY,
        ),
        (3, 3) => verify_shape::<3, 3>(
            pool_tree_bytes,
            data,
            settlement,
            &proof,
            &verifying_keys::spp_3_3::VERIFYINGKEY,
        ),
        (5, 3) => verify_shape::<5, 3>(
            pool_tree_bytes,
            data,
            settlement,
            &proof,
            &verifying_keys::spp_5_3::VERIFYINGKEY,
        ),
        _ => Err(ShieldedPoolError::InvalidTransactShape.into()),
    }
}

fn verify_shape<const N: usize, const M: usize>(
    pool_tree_bytes: &mut [u8],
    data: &TransactData,
    settlement: &SettlementAccounts<'_>,
    proof: &Bsb22Proof,
    verifying_key: &groth16_solana_bsb22::groth16::Groth16Verifyingkey,
) -> ProgramResult {
    let public_input_hash = public_input_hash::<N, M>(pool_tree_bytes, data, settlement)?;
    let public_inputs = [public_input_hash];
    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof.a,
        &proof.b,
        &proof.c,
        &proof.commitment,
        &proof.commitment_pok,
        &public_inputs,
        verifying_key,
    )
    .map_err(|_| {
        log("transact: SPP BSB22 verifier initialization failed");
        ProgramError::from(ShieldedPoolError::TransactProofVerificationFailed)
    })?;
    verifier.verify().map_err(|_| {
        log("transact: SPP Groth16 verification failed");
        ProgramError::from(ShieldedPoolError::TransactProofVerificationFailed)
    })
}

pub fn canonical_shape(data: &TransactData) -> Result<(usize, usize), ProgramError> {
    let inputs = data.nullifiers.len();
    let outputs = data.output_utxo_hashes.len();
    if inputs > SPP_MAX_INPUTS || outputs > SPP_MAX_OUTPUTS {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    // The v1 wire format does not carry an explicit shape. Use the smallest
    // spec circuit that can carry the active vectors so proof verification has
    // a single canonical verifying key.
    match (inputs, outputs) {
        (0 | 1, 0..=2) => Ok((1, 2)),
        (0 | 1, 3..=8) => Ok((1, 8)),
        (2, 0..=2) => Ok((2, 2)),
        (2..=3, 0..=3) => Ok((3, 3)),
        (4..=5, 0..=3) => Ok((5, 3)),
        _ => Err(ShieldedPoolError::InvalidTransactShape.into()),
    }
}

fn public_input_hash<const N: usize, const M: usize>(
    pool_tree_bytes: &mut [u8],
    data: &TransactData,
    settlement: &SettlementAccounts<'_>,
) -> Result<[u8; 32], ProgramError> {
    if data.nullifiers.len() > N || data.output_utxo_hashes.len() > M {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    let nullifiers = padded_values::<N>(&data.nullifiers);
    let output_utxo_hashes = padded_values::<M>(&data.output_utxo_hashes);
    let utxo_tree_roots = input_roots::<N>(pool_tree_bytes, data)?;
    let nullifier_roots = nullifier_roots::<N>(pool_tree_bytes, data)?;
    let external_data_hash = external_data_hash(data, settlement)?;
    let public_sol_amount = signed_public_sol_amount(data)?;
    let public_spl_amount = signed_public_amount(data.public_amount_mode, data.public_spl_amount)?;
    let public_spl_asset = public_spl_asset(data, settlement)?;
    let solana_pk_hashes = solana_pk_hashes::<N>(data, settlement)?;

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
        hash_chain(&solana_pk_hashes)?,
    ])
}

struct Bsb22Proof {
    a: [u8; 64],
    b: [u8; 128],
    c: [u8; 64],
    commitment: [u8; 64],
    commitment_pok: [u8; 64],
}

fn bsb22_proof(proof: &[u8; 192]) -> Result<Bsb22Proof, ProgramError> {
    if proof[128..160] == [0u8; 32] || proof[160..192] == [0u8; 32] {
        log("transact: SPP BSB22 proof is missing commitment fields");
        return Err(ShieldedPoolError::InvalidTransactProofEncoding.into());
    }

    let proof_a: [u8; 32] = proof[..32]
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?;
    let proof_b: [u8; 64] = proof[32..96]
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?;
    let proof_c: [u8; 32] = proof[96..128]
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?;
    let commitment: [u8; 32] = proof[128..160]
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?;
    let commitment_pok: [u8; 32] = proof[160..192]
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?;

    Ok(Bsb22Proof {
        a: decompression::decompress_g1(&proof_a)
            .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?,
        b: decompression::decompress_g2(&proof_b)
            .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?,
        c: decompression::decompress_g1(&proof_c)
            .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?,
        commitment: decompression::decompress_g1(&commitment)
            .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?,
        commitment_pok: decompression::decompress_g1(&commitment_pok)
            .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding)?,
    })
}

fn public_spl_asset(
    data: &TransactData,
    settlement: &SettlementAccounts<'_>,
) -> Result<[u8; 32], ProgramError> {
    if data.public_spl_amount.unwrap_or(0) == 0 {
        return Ok(EMPTY_FIELD);
    }
    let asset_pubkey = spl_asset_pubkey(settlement)?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(asset_pubkey.as_ref());
    solana_pk_hash(&bytes)
}

fn input_roots<const N: usize>(
    pool_tree_bytes: &[u8],
    data: &TransactData,
) -> Result<[[u8; 32]; N], ProgramError> {
    let mut roots = [[0u8; 32]; N];
    for (i, root_index) in data.utxo_tree_root_index.iter().enumerate() {
        roots[i] = state_root_by_index(pool_tree_bytes, *root_index)
            .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
    }
    Ok(roots)
}

fn nullifier_roots<const N: usize>(
    pool_tree_bytes: &[u8],
    data: &TransactData,
) -> Result<[[u8; 32]; N], ProgramError> {
    let mut roots = [[0u8; 32]; N];
    for (i, root_index) in data.nullifier_tree_root_index.iter().enumerate() {
        roots[i] = nullifier_root_by_index(pool_tree_bytes, *root_index)
            .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
    }
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

    let instruction_discriminator = [tag::TRANSACT];
    Ok(sha256_be_field_hash(&[
        instruction_discriminator.as_slice(),
        data.sender_view_tag.as_slice(),
        relayer_fee.as_slice(),
        public_sol_amount.as_slice(),
        public_spl_amount.as_slice(),
        user_sol_account.as_slice(),
        user_spl_token_account.as_slice(),
        spl_token_interface.as_slice(),
        data.encrypted_utxos.as_slice(),
    ]))
}

fn solana_pk_hashes<const N: usize>(
    data: &TransactData,
    settlement: &SettlementAccounts<'_>,
) -> Result<[[u8; 32]; N], ProgramError> {
    let mut out = [[0u8; 32]; N];
    for (i, hash) in out.iter_mut().enumerate().take(data.nullifiers.len()) {
        if settlement.solana_owner_pubkeys[i] == EMPTY_FIELD {
            continue;
        }
        *hash = solana_pk_hash(&settlement.solana_owner_pubkeys[i])?;
    }
    Ok(out)
}

fn solana_pk_hash(pubkey: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let pk_low = field_from_u128_be(&pubkey[16..]);
    let pk_high = field_from_u128_be(&pubkey[..16]);
    Poseidon::hashv(&[pk_low.as_slice(), pk_high.as_slice()])
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
    Ok(sha256_be_field_hash(&[settlement
        .signer
        .address()
        .as_ref()]))
}

fn sha256_be_field_hash(slices: &[&[u8]]) -> [u8; 32] {
    let mut out = sha256_hashv(slices).to_bytes();
    // Keep the encoded value inside BN254 Fr. This matches the prover's
    // Sha256BE-to-field convention while avoiding on-chain modular reduction.
    out[0] = 0;
    out
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

fn field_from_u128_be(value: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(value);
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
