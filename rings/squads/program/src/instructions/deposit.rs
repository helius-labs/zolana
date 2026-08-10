//! `deposit` (tag 1): move funds into the shielded pool through the ring. A
//! fully public deposit with no proof and no co-signer. Settles through the
//! SPP's proofless `ring_deposit` in the same transaction.

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_squads_interface::{
    constants::VIEWING_KEY_STATE_ACTIVE, error::SquadsRingError,
    instruction::instruction_data::DepositIxData, RING_AUTH_PDA_SEED,
};

use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::{
    cpi::spp_ring_deposit,
    pda::verify_pda,
    proof::poseidon2,
    spp_deposit::{build_spp_ring_deposit_data, SppRingDepositParams},
};

/// SOL settlement forwards three accounts (`system_program`, `sol_interface`,
/// `user_sol`). SPL forwards four (`user_token`, `vault`, `registry`,
/// `token_program`).
const SOL_SETTLEMENT_ACCOUNTS: usize = 3;
const SPL_SETTLEMENT_ACCOUNTS: usize = 4;

/// The `deposit` accounts in instruction order. `settlement` is the SOL or SPL
/// account tail SPP infers the asset from and receives verbatim.
struct DepositAccounts<'a> {
    depositor: &'a AccountView,
    recipient_vka: &'a AccountView,
    ring_auth: &'a AccountView,
    spp_program: &'a AccountView,
    tree: &'a AccountView,
    settlement: &'a [AccountView],
}

impl<'a> DepositAccounts<'a> {
    fn validate_and_parse(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let depositor = iter.next_account("depositor")?;
        let recipient_vka = iter.next_account("recipient_viewing_key_account")?;
        let ring_auth = iter.next_account("ring_auth")?;
        let spp_program = iter.next_account("spp_program")?;
        let tree = iter.next_account("tree")?;
        let settlement = iter.remaining_unchecked()?;
        Ok(Self {
            depositor,
            recipient_vka,
            ring_auth,
            spp_program,
            tree,
            settlement,
        })
    }
}

#[inline(never)]
pub fn process_deposit_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        DepositIxData::deserialize(data).map_err(|_| SquadsRingError::InvalidInstructionData)?;

    let accs = DepositAccounts::validate_and_parse(accounts)?;

    if !accs.depositor.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }

    let settlement_len = accs.settlement.len();
    if settlement_len != SOL_SETTLEMENT_ACCOUNTS && settlement_len != SPL_SETTLEMENT_ACCOUNTS {
        return Err(SquadsRingError::InvalidDepositAccounts.into());
    }

    // The deposited UTXO's owner hash matches the ring spend circuit's
    // `OwnerHashGadget`, so a later `transact` can spend it.
    let vka = load_viewing_key_account(accs.recipient_vka)?;
    // A blocked account can only exit through `full_withdrawal`, so a deposit
    // into it would be funds the owner deliberately stopped using.
    if vka.state != VIEWING_KEY_STATE_ACTIVE {
        return Err(SquadsRingError::ViewingKeyAccountBlocked.into());
    }
    let owner = poseidon2(
        &vka.owner.to_bytes(),
        &vka.nullifier_pubkey,
        SquadsRingError::ProofHashingFailed,
    )?;

    let ring_auth_bump = verify_pda(accs.ring_auth.address(), &[RING_AUTH_PDA_SEED], &crate::ID)?;

    // Binds the deposit to the recipient the viewing key account names. SPP
    // sees only this hash, so the program must nest the owner itself rather
    // than trust a caller-supplied one.
    let owner_utxo_hash = poseidon2(&owner, &ix.blinding, SquadsRingError::ProofHashingFailed)?;

    let spp_data = build_spp_ring_deposit_data(SppRingDepositParams {
        view_tag: ix.view_tag,
        owner_utxo_hash,
        asset: ix.asset,
        amount: ix.amount,
        encrypted: ix.encrypted,
    })?;

    // In SPP's `ring_deposit` order `ring_auth` is SPP's `RingConfig`. SPP
    // reads a trailing program account, so the SPP program is forwarded too.
    let mut cpi_accounts: Vec<&AccountView> = Vec::with_capacity(4 + settlement_len);
    cpi_accounts.push(accs.tree);
    cpi_accounts.push(accs.depositor);
    cpi_accounts.push(accs.ring_auth);
    for account in accs.settlement {
        cpi_accounts.push(account);
    }
    cpi_accounts.push(accs.spp_program);

    spp_ring_deposit(accs.spp_program, &cpi_accounts, &spp_data, ring_auth_bump)
}
