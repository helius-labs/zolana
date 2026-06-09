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
    instructions::create_pool_tree::init::{
        current_nullifier_root_index, nullifier_root_by_index, state_root_by_index,
    },
    instructions::hash::{field_from_u64, hash_chain, EMPTY_FIELD},
    log::log,
};

const SPP_MAX_INPUTS: usize = 5;
const SPP_MAX_OUTPUTS: usize = 8;
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
        (2, 2) => verify_shape::<2, 2>(
            pool_tree_bytes,
            data,
            settlement,
            &proof,
            &verifying_keys::spp_2_2::VERIFYINGKEY,
        ),
        (1, 2) => verify_shape::<1, 2>(
            pool_tree_bytes,
            data,
            settlement,
            &proof,
            &verifying_keys::spp_1_2::VERIFYINGKEY,
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
        (1, 8) => verify_shape::<1, 8>(
            pool_tree_bytes,
            data,
            settlement,
            &proof,
            &verifying_keys::spp_1_8::VERIFYINGKEY,
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
    let public_input_hash = public_input_hash_from_data::<N, M>(pool_tree_bytes, data, settlement)?;
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

    // Supported circuit shapes, smallest-capacity first. A transaction is proven
    // with the first shape that can hold its real inputs/outputs; the remaining
    // slots are dummy-padded in-circuit and reconstructed as zeros here. The Go
    // prover enforces the same smallest-fit rule (protocol.CanonicalShape), so
    // the vkey and public-input padding agree.
    const SHAPES: [(usize, usize); 5] = [(1, 2), (2, 2), (3, 3), (5, 3), (1, 8)];
    for &(n, m) in SHAPES.iter() {
        if inputs <= n && outputs <= m {
            return Ok((n, m));
        }
    }
    Err(ShieldedPoolError::InvalidTransactShape.into())
}

fn public_input_hash_from_data<const N: usize, const M: usize>(
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

    public_input_hash(PublicInputs {
        nullifiers: &nullifiers,
        output_utxo_hashes: &output_utxo_hashes,
        utxo_tree_roots: &utxo_tree_roots,
        nullifier_roots: &nullifier_roots,
        private_tx_hash: data.private_tx_hash,
        p256_message_hash: p256_message_hash(&data.private_tx_hash),
        external_data_hash,
        public_sol_amount,
        public_spl_amount,
        public_spl_asset,
        program_id_hashchain: EMPTY_FIELD,
        solana_pubkey_hash: signer_pubkey_hash(settlement)?,
        data_hash: EMPTY_FIELD,
        zone_data_hash: EMPTY_FIELD,
        solana_pk_hashes: &solana_pk_hashes,
    })
}

struct PublicInputs<'a> {
    nullifiers: &'a [[u8; 32]],
    output_utxo_hashes: &'a [[u8; 32]],
    utxo_tree_roots: &'a [[u8; 32]],
    nullifier_roots: &'a [[u8; 32]],
    private_tx_hash: [u8; 32],
    p256_message_hash: [u8; 32],
    external_data_hash: [u8; 32],
    public_sol_amount: [u8; 32],
    public_spl_amount: [u8; 32],
    public_spl_asset: [u8; 32],
    program_id_hashchain: [u8; 32],
    solana_pubkey_hash: [u8; 32],
    data_hash: [u8; 32],
    zone_data_hash: [u8; 32],
    solana_pk_hashes: &'a [[u8; 32]],
}

fn public_input_hash(inputs: PublicInputs<'_>) -> Result<[u8; 32], ProgramError> {
    let error = ShieldedPoolError::TransactProofVerificationFailed;
    hash_chain(
        &[
            hash_chain(inputs.nullifiers, error)?,
            hash_chain(inputs.output_utxo_hashes, error)?,
            hash_chain(inputs.utxo_tree_roots, error)?,
            hash_chain(inputs.nullifier_roots, error)?,
            inputs.private_tx_hash,
            inputs.p256_message_hash,
            inputs.external_data_hash,
            inputs.public_sol_amount,
            inputs.public_spl_amount,
            inputs.public_spl_asset,
            inputs.program_id_hashchain,
            inputs.solana_pubkey_hash,
            inputs.data_hash,
            inputs.zone_data_hash,
            hash_chain(inputs.solana_pk_hashes, error)?,
        ],
        error,
    )
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
    // Non-inclusion must be proven against the CURRENT nullifier root only.
    //
    // The nullifier root history is a ring of past roots, but unlike Light's
    // batched tree it is never invalidated when a queue bloom filter is zeroed.
    // A spent nullifier's bloom is wiped ~1-2 forester rounds after it lands,
    // while a pre-spend root stays selectable for ~200 batches — so proving
    // non-inclusion against a stale root (where the nullifier was still absent)
    // while its bloom is gone would let the same UTXO be spent twice. Forcing
    // the current root closes that window: the latest root includes every
    // applied nullifier, and anything still only in the queue is caught by its
    // live bloom on insert.
    //
    // TODO(nullifier-root-grace-window): restore a bounded grace window by
    // mirroring Light's zero_out_roots — zero stale SPP nullifier roots when the
    // corresponding queue bloom is wiped — so concurrent proofs against a
    // recent-but-not-latest root still verify. Requires per-root coverage
    // tracking and validating the Light-queue/SPP-tree index mapping under a
    // batch-update repro test.
    let current = current_nullifier_root_index(pool_tree_bytes)
        .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
    let mut roots = [[0u8; 32]; N];
    for (i, root_index) in data.nullifier_tree_root_index.iter().enumerate() {
        if *root_index != current {
            return Err(ShieldedPoolError::StaleNullifierRoot.into());
        }
        roots[i] = nullifier_root_by_index(pool_tree_bytes, *root_index)
            .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
    }
    Ok(roots)
}

fn external_data_hash(
    data: &TransactData,
    settlement: &SettlementAccounts<'_>,
) -> Result<[u8; 32], ProgramError> {
    // Keep this field order stable; proofs bind to this transcript (spec
    // §SPP Proof). expiry_unix_ts is in the preimage (after relayer_fee) so the
    // on-chain clock check enforces the owner-committed value: SPP cannot
    // recompute private_tx_hash (it covers private input hashes), so binding
    // expiry only there would let a relayer submit with an arbitrary
    // data.expiry_unix_ts.
    let relayer_fee = data.relayer_fee.to_be_bytes();
    let expiry_unix_ts = data.expiry_unix_ts.to_be_bytes();
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
        expiry_unix_ts.as_slice(),
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

pub(crate) fn solana_pk_hash(pubkey: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
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

fn p256_message_hash(private_tx_hash: &[u8; 32]) -> [u8; 32] {
    // Sha256BE(private_tx_hash) per spec: SHA-256 with the most-significant byte
    // zeroed (keeps digest[1..32]). Same convention as external_data_hash.
    sha256_be_field_hash(&[private_tx_hash.as_slice()])
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

fn padded_values<const N: usize>(values: &[[u8; 32]]) -> [[u8; 32]; N] {
    let mut out = [[0u8; 32]; N];
    out[..values.len()].copy_from_slice(values);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn transact_data_shape(inputs: usize, outputs: usize) -> TransactData {
        TransactData {
            expiry_unix_ts: u64::MAX,
            sender_view_tag: [0u8; 32],
            proof: [0u8; 192],
            relayer_fee: 0,
            public_amount_mode: PUBLIC_AMOUNT_NONE,
            nullifiers: vec![[1u8; 32]; inputs],
            output_utxo_hashes: vec![[2u8; 32]; outputs],
            utxo_tree_root_index: vec![0; inputs],
            nullifier_tree_root_index: vec![0; inputs],
            private_tx_hash: [3u8; 32],
            public_sol_amount: None,
            public_spl_amount: None,
            cpi_signer: None,
            in_utxo_signer_indices: None,
            encrypted_utxos: vec![],
            requires_p256: true,
        }
    }

    #[test]
    fn nullifier_roots_require_current_root_index() {
        use crate::instructions::create_pool_tree::init::{
            init_pool_tree_account, pool_tree_account_size, push_nullifier_root,
        };
        use pinocchio::Address;

        let mut buf = vec![0u8; pool_tree_account_size()];
        let owner = Address::new_from_array([1u8; 32]);
        let tree_pubkey = Address::new_from_array([2u8; 32]);
        init_pool_tree_account(&mut buf, &owner, &tree_pubkey).expect("init pool tree");
        // Seed root is at index 0. Advance the ring so the current index is 1
        // and index 0 is a valid-but-stale historical root.
        push_nullifier_root(&mut buf, [7u8; 32]).expect("push root");
        assert_eq!(current_nullifier_root_index(&buf).unwrap(), 1);

        // A stale (non-current) root index is rejected even though it still
        // resolves to a real root in the ring — this is the double-spend guard.
        let mut data = transact_data_shape(1, 2);
        data.nullifier_tree_root_index = vec![0];
        assert!(
            nullifier_roots::<1>(&buf, &data).is_err(),
            "stale nullifier root index must be rejected"
        );

        // The current root index is accepted and resolves to the latest root.
        data.nullifier_tree_root_index = vec![1];
        assert_eq!(nullifier_roots::<1>(&buf, &data).unwrap()[0], [7u8; 32]);
    }

    #[test]
    fn canonical_shape_matches_supported_vkeys() {
        // Exact arities map to themselves.
        let supported = [(2, 2), (1, 2), (3, 3), (5, 3), (1, 8)];
        for shape in supported {
            let data = transact_data_shape(shape.0, shape.1);
            assert_eq!(canonical_shape(&data).unwrap(), shape);
        }

        // Smaller arities map to the smallest shape with capacity; the unused
        // slots are dummy-padded (shield: 0 inputs, full unshield: 0 outputs).
        // Mirrors TestCanonicalShapeMatchesOnChainSelection in Go.
        let padded = [
            ((0, 1), (1, 2)),
            ((0, 2), (1, 2)),
            ((1, 0), (1, 2)),
            ((1, 1), (1, 2)),
            ((2, 1), (2, 2)),
            ((3, 1), (3, 3)),
            ((4, 3), (5, 3)),
            ((0, 8), (1, 8)),
            ((1, 4), (1, 8)),
        ];
        for (real, want) in padded {
            let data = transact_data_shape(real.0, real.1);
            assert_eq!(canonical_shape(&data).unwrap(), want, "{real:?}");
        }

        // Arities no supported shape can hold are rejected.
        for shape in [(6, 1), (2, 4), (1, 9), (2, 8)] {
            let data = transact_data_shape(shape.0, shape.1);
            assert!(canonical_shape(&data).is_err(), "{shape:?}");
        }
    }

    #[test]
    fn p256_message_hash_is_sha256_be() {
        let mut private_tx_hash = [0u8; 32];
        for (i, byte) in private_tx_hash.iter_mut().enumerate() {
            *byte = (i + 1) as u8;
        }

        // Sha256BE: SHA-256 then zero the most-significant byte (keep digest[1..32]).
        let got = p256_message_hash(&private_tx_hash);
        let mut want = sha256_hashv(&[private_tx_hash.as_slice()]).to_bytes();
        want[0] = 0;

        assert_eq!(got, want);
        assert_eq!(got[0], 0);
    }

    #[test]
    fn public_input_hash_matches_known_answer_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../prover/server/prover/spp/testdata/public_input_hash_vector.json"
        ))
        .unwrap();

        let nullifiers = field_vec(&vector, "nullifiers");
        let output_utxo_hashes = field_vec(&vector, "output_utxo_hashes");
        let utxo_tree_roots = field_vec(&vector, "utxo_tree_roots");
        let nullifier_roots = field_vec(&vector, "nullifier_roots");
        let solana_pk_hashes = field_vec(&vector, "solana_pk_hashes");

        let got = public_input_hash(PublicInputs {
            nullifiers: &nullifiers,
            output_utxo_hashes: &output_utxo_hashes,
            utxo_tree_roots: &utxo_tree_roots,
            nullifier_roots: &nullifier_roots,
            private_tx_hash: field(&vector, "private_tx_hash"),
            p256_message_hash: field(&vector, "p256_message_hash"),
            external_data_hash: field(&vector, "external_data_hash"),
            public_sol_amount: field(&vector, "public_sol_amount"),
            public_spl_amount: field(&vector, "public_spl_amount"),
            public_spl_asset: field(&vector, "public_spl_asset_pubkey"),
            program_id_hashchain: field(&vector, "program_id_hashchain"),
            solana_pubkey_hash: field(&vector, "solana_pubkey_hash"),
            data_hash: field(&vector, "data_hash"),
            zone_data_hash: field(&vector, "zone_data_hash"),
            solana_pk_hashes: &solana_pk_hashes,
        })
        .unwrap();

        assert_eq!(got, field(&vector, "public_input_hash"));
    }

    #[test]
    fn field_derivations_match_known_answer_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../prover/server/prover/spp/testdata/field_derivation_vector.json"
        ))
        .unwrap();

        let external = &vector["external_data_hash"];
        let instruction = [external["instruction_discriminator"].as_u64().unwrap() as u8];
        let sender_view_tag = field(external, "sender_view_tag");
        let relayer_fee = (external["relayer_fee"].as_u64().unwrap() as u16).to_be_bytes();
        let expiry_unix_ts = external["expiry_unix_ts"].as_u64().unwrap().to_be_bytes();
        let public_sol_amount = external["public_sol_amount"]
            .as_u64()
            .unwrap()
            .to_be_bytes();
        let public_spl_amount = external["public_spl_amount"]
            .as_u64()
            .unwrap()
            .to_be_bytes();
        let user_sol_account = field(external, "user_sol_account");
        let user_spl_token_account = field(external, "user_spl_token_account");
        let spl_token_interface = field(external, "spl_token_interface");
        let encrypted_utxos = bytes(external, "encrypted_utxos");
        let got_external = sha256_be_field_hash(&[
            instruction.as_slice(),
            sender_view_tag.as_slice(),
            relayer_fee.as_slice(),
            expiry_unix_ts.as_slice(),
            public_sol_amount.as_slice(),
            public_spl_amount.as_slice(),
            user_sol_account.as_slice(),
            user_spl_token_account.as_slice(),
            spl_token_interface.as_slice(),
            encrypted_utxos.as_slice(),
        ]);
        assert_eq!(got_external, field(external, "hash"));

        let solana = &vector["solana_pk_hash"];
        assert_eq!(
            solana_pk_hash(&field(solana, "pubkey")).unwrap(),
            field(solana, "hash")
        );

        let p256 = &vector["p256_message_hash"];
        assert_eq!(
            p256_message_hash(&field(p256, "private_tx_hash")),
            field(p256, "hash")
        );

        for item in vector["negative_u64"].as_array().unwrap() {
            let amount = item["amount"].as_u64().unwrap();
            assert_eq!(negative_field_from_u64(amount), field(item, "field"));
        }

        for item in vector["public_amounts"].as_array().unwrap() {
            let mut data = transact_data_shape(1, 2);
            data.public_amount_mode = item["mode"].as_u64().unwrap() as u8;
            data.relayer_fee = item["relayer_fee"].as_u64().unwrap() as u16;
            data.public_sol_amount = Some(item["public_sol_amount"].as_u64().unwrap());
            data.public_spl_amount = Some(item["public_spl_amount"].as_u64().unwrap());

            assert_eq!(signed_public_sol_amount(&data).unwrap(), field(item, "sol"));
            assert_eq!(
                signed_public_amount(data.public_amount_mode, data.public_spl_amount).unwrap(),
                field(item, "spl")
            );
        }
    }

    fn field_vec(vector: &serde_json::Value, key: &str) -> Vec<[u8; 32]> {
        vector[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| decode_field(value.as_str().unwrap()))
            .collect()
    }

    fn field(vector: &serde_json::Value, key: &str) -> [u8; 32] {
        decode_field(vector[key].as_str().unwrap())
    }

    fn bytes(vector: &serde_json::Value, key: &str) -> Vec<u8> {
        let mut digits = vector[key]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap_or(vector[key].as_str().unwrap())
            .to_owned();
        if digits.len() % 2 == 1 {
            digits.insert(0, '0');
        }
        hex::decode(&digits).unwrap()
    }

    fn decode_field(value: &str) -> [u8; 32] {
        let mut digits = value.strip_prefix("0x").unwrap_or(value).to_owned();
        if digits.len() % 2 == 1 {
            digits.insert(0, '0');
        }
        let bytes = hex::decode(&digits).unwrap();
        assert!(bytes.len() <= 32);

        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }
}
