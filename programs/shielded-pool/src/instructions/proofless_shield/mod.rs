use light_hasher::{Hasher, Poseidon};
use pinocchio::{
    cpi::invoke, error::ProgramError, instruction::InstructionView, AccountView, Address,
    ProgramResult,
};
use zolana_interface::event::{
    encode_event_instruction, encode_output_data, DepositWithdraw, EventKind, GeneralEvent,
    OutputData, ProoflessOutput,
};
use zolana_interface::instruction::instruction_data::proofless_shield::CpiSignerData;
use zolana_interface::instruction::{
    OutputUtxo, ProoflessShieldIxData, ZoneProoflessShieldIxData, PUBLIC_AMOUNT_DEPOSIT_SOL,
    PUBLIC_AMOUNT_DEPOSIT_SPL,
};
use zolana_interface::UTXO_DOMAIN;
use zolana_interface::ZONE_AUTH_PDA_SEED;

use crate::instructions::{
    accounts::{load_transact_accounts, TransactSettlement, CPI_SIGNER_SEED},
    hash::{field_from_u64, solana_pk_hash},
    settlement::{settle_public_amounts, spl_asset_pubkey},
};
use crate::error::ShieldedPoolError;
use zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR;
use zolana_tree::TreeAccount;

struct Deposit {
    view_tag: [u8; 32],
    owner_utxo_hash: [u8; 32],
    salt: [u8; 16],
    public_amount: Option<u64>,
    public_amount_mode: u8,
    cpi_signer: Option<CpiSignerData>,
    cpi_signer_seed: &'static [u8],
    program_data_hash: Option<[u8; 32]>,
    program_data: Option<Vec<u8>>,
    policy_data_hash: Option<[u8; 32]>,
    zone_data: Option<Vec<u8>>,
}

pub fn process_proofless_shield(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: ProoflessShieldIxData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if !accounts[1].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.cpi_signer.is_some() {
        let cpi_signer = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
        if !cpi_signer.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }
    if (data.program_data_hash.is_some() || data.program_data.is_some())
        && data.cpi_signer.is_none()
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    process_deposit(
        program_id,
        accounts,
        Deposit {
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_amount: data.public_amount,
            public_amount_mode: data.public_amount_mode,
            cpi_signer: data.cpi_signer,
            cpi_signer_seed: CPI_SIGNER_SEED,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data,
            policy_data_hash: None,
            zone_data: None,
        },
    )
}

pub fn process_zone_proofless_shield(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: ZoneProoflessShieldIxData,
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if !accounts[1].is_signer() || !accounts[2].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    process_deposit(
        program_id,
        accounts,
        Deposit {
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_amount: data.public_amount,
            public_amount_mode: data.public_amount_mode,
            cpi_signer: Some(data.cpi_signer),
            cpi_signer_seed: ZONE_AUTH_PDA_SEED,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data,
            policy_data_hash: data.policy_data_hash,
            zone_data: data.zone_data,
        },
    )
}

fn process_deposit(
    program_id: &Address,
    accounts: &mut [AccountView],
    d: Deposit,
) -> ProgramResult {
    // Proofless shields are deposit-only; reject withdraw / NONE / unknown modes.
    let needs_spl = match d.public_amount_mode {
        PUBLIC_AMOUNT_DEPOSIT_SOL => false,
        PUBLIC_AMOUNT_DEPOSIT_SPL => true,
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    };
    let amount = d.public_amount.unwrap_or(0);

    let Some((program_account, head)) = accounts.split_last_mut() else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if program_account.address() != program_id {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let tx = deposit_settlement(&d);
    let verified = load_transact_accounts(program_id, head, &tx, d.cpi_signer_seed)?;

    let (asset, asset_field) = if needs_spl {
        let mint = spl_asset_pubkey(&verified.settlement)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(mint.as_ref());
        (bytes, solana_pk_hash(&bytes)?)
    } else {
        ([0u8; 32], solana_pk_hash(&[0u8; 32])?)
    };

    let zero = [0u8; 32];
    let program_data_hash = d.program_data_hash.unwrap_or(zero);
    let policy_data_hash = d.policy_data_hash.unwrap_or(zero);
    let zone_program_id = match d.cpi_signer {
        Some(cpi) => solana_pk_hash(&cpi.program_id)?,
        None => zero,
    };
    let utxo_hash = Poseidon::hashv(&[
        field_from_u64(u64::from(UTXO_DOMAIN)).as_slice(),
        asset_field.as_slice(),
        field_from_u64(amount).as_slice(),
        program_data_hash.as_slice(),
        policy_data_hash.as_slice(),
        zone_program_id.as_slice(),
        d.owner_utxo_hash.as_slice(),
    ])
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let mut output_tree = [0u8; 32];
    output_tree.copy_from_slice(verified.tree.address().as_ref());
    let first_output_leaf_index = {
        let mut tree = TreeAccount::from_account_view_mut(
            verified.tree,
            program_id,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(ShieldedPoolError::from)?;
        let index = tree.utxo_tree.next_index();
        tree.utxo_tree.append(utxo_hash);
        index
    };

    settle_public_amounts(program_id, &verified.settlement, &tx)?;

    let output_data = encode_output_data(&OutputData::Proofless(ProoflessOutput {
        owner_utxo_hash: d.owner_utxo_hash,
        salt: d.salt,
        program_data_hash: d.program_data_hash,
        program_data: d.program_data,
        zone_program_id: d.cpi_signer.map(|cpi| cpi.program_id),
        policy_data_hash: d.policy_data_hash,
        zone_data: d.zone_data,
    }));
    let event = GeneralEvent {
        inputs: Vec::new(),
        outputs: vec![OutputUtxo {
            view_tag: d.view_tag,
            utxo_hash,
            data: output_data,
        }],
        // Proofless shields are Solana-rail deposits with no shared P256
        // viewing key; the field is zeroed so indexers skip ECDH decryption.
        tx_viewing_pk: [0u8; 33],
        first_output_leaf_index,
        output_tree,
        relay_fee: None,
        deposit_withdraw: Some(DepositWithdraw {
            is_deposit: true,
            amount,
            asset: needs_spl.then_some(asset),
        }),
    };
    emit_event(program_id, event)
}

fn emit_event(program_id: &Address, event: GeneralEvent) -> ProgramResult {
    let data = encode_event_instruction(EventKind::ProoflessShield, &event);
    let instruction_accounts = [];
    let instruction = InstructionView {
        program_id,
        accounts: &instruction_accounts,
        data: &data,
    };
    let accounts: [&AccountView; 0] = [];
    invoke(&instruction, &accounts)
}

fn deposit_settlement(d: &Deposit) -> TransactSettlement<'static> {
    TransactSettlement {
        cpi_signer: d.cpi_signer,
        inputs_len: 0,
        in_utxo_signer_indices: None,
        public_amount_mode: d.public_amount_mode,
        public_amount: d.public_amount,
        relayer_fee: 0,
    }
}
