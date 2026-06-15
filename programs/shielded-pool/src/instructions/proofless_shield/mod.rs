use light_hasher::{Hasher, Poseidon};
use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::event::{encode_event_instruction, ShieldedPoolEvent};
use zolana_interface::instruction::{
    CpiSignerData, ProoflessShieldEvent, ProoflessShieldIxData, TransactIxData,
    ZoneProoflessShieldIxData, PUBLIC_AMOUNT_DEPOSIT_SOL, PUBLIC_AMOUNT_DEPOSIT_SPL,
};
use zolana_interface::{SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED, UTXO_DOMAIN};

use crate::instructions::{
    accounts::{load_transact_accounts, CPI_SIGNER_SEED, ZONE_AUTH_SEED},
    hash::{field_from_u64, solana_pk_hash},
    settlement::{settle_public_amounts, spl_asset_pubkey},
};
use crate::{
    error::ShieldedPoolError,
    instructions::{create_tree::init::append_state_leaves as append_to_pool, loader},
    log::log,
};

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
            cpi_signer_seed: ZONE_AUTH_SEED,
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

    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    // The trailing self-program account is required for `emit_event` self-CPI.
    let (head, program_slice) = accounts.split_at_mut(accounts.len() - 1);
    if program_slice[0].address() != program_id {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let tx = deposit_view(&d);
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

    {
        let bytes = loader::account_data_mut(verified.tree);
        if append_to_pool(bytes, &[utxo_hash]).is_err() {
            log("proofless_shield: state sub-tree append failed");
            return Err(ShieldedPoolError::StateAppendFailed.into());
        }
    }

    settle_public_amounts(program_id, &verified.settlement, &tx)?;

    let event = ProoflessShieldEvent {
        view_tag: d.view_tag,
        utxo_hash,
        asset,
        amount,
        zone_program_id: d.cpi_signer.map(|cpi| cpi.program_id),
        policy_data_hash: d.policy_data_hash,
        owner_utxo_hash: d.owner_utxo_hash,
        salt: d.salt,
        program_data_hash: d.program_data_hash,
        program_data: d.program_data,
        zone_data: d.zone_data,
    };
    let cpi_authority = verified
        .settlement
        .cpi_authority
        .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
    let cpi_authority_bump = verified
        .settlement
        .cpi_authority_bump
        .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
    emit_event(
        program_id,
        cpi_authority,
        cpi_authority_bump,
        ShieldedPoolEvent::ProoflessShield(event),
    )
}

fn emit_event(
    program_id: &Address,
    cpi_authority: &AccountView,
    cpi_authority_bump: u8,
    event: ShieldedPoolEvent,
) -> ProgramResult {
    let data = encode_event_instruction(&event);
    let instruction_accounts = [InstructionAccount::readonly_signer(cpi_authority.address())];
    let instruction = InstructionView {
        program_id,
        accounts: &instruction_accounts,
        data: &data,
    };
    let bump = [cpi_authority_bump];
    let seeds = [
        Seed::from(SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED),
        Seed::from(&bump),
    ];
    let signer = Signer::from(&seeds);
    invoke_signed(
        &instruction,
        &[cpi_authority],
        core::slice::from_ref(&signer),
    )
}

fn deposit_view(d: &Deposit) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: 0,
        sender_view_tag: [0u8; 32],
        proof: [0u8; 192],
        private_tx_hash: [0u8; 32],
        relayer_fee: 0,
        public_amount_mode: d.public_amount_mode,
        // Proofless deposits verify no proof; the rail is irrelevant here (this
        // view only drives settlement account loading).
        requires_p256: false,
        public_amount: d.public_amount,
        // Drives the cpi_signer PDA check (seed per d.cpi_signer_seed) and
        // reserves account index 2 for the signer in the settlement layout.
        cpi_signer: d.cpi_signer,
        inputs: Vec::new(),
        output_utxo_hashes: Vec::new(),
        in_utxo_signer_indices: None,
        encrypted_utxos: Vec::new(),
    }
}
