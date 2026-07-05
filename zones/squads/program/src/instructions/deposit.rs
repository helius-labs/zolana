//! `deposit` (tag 1): move funds into the shielded pool through the zone. A fully
//! public deposit; no proof and no co-signer. Settles through the SPP's proofless
//! `zone_deposit` in the same transaction.

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_squads_interface::{
    error::SquadsZoneError, instruction::instruction_data::DepositIxData, ZONE_AUTH_PDA_SEED,
};

use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::{
    cpi::spp_zone_deposit,
    pda::verify_pda,
    proof::poseidon2,
    spp_deposit::{build_spp_zone_deposit_data, SppZoneDepositParams},
};

/// SOL settlement forwards three accounts (`system_program`, `sol_interface`,
/// `user_sol`); SPL forwards four (`user_token`, `vault`, `registry`,
/// `token_program`). Any other count is malformed.
const SOL_SETTLEMENT_ACCOUNTS: usize = 3;
const SPL_SETTLEMENT_ACCOUNTS: usize = 4;

/// The `deposit` accounts in instruction order. `settlement` is the SOL or SPL
/// account tail SPP infers the asset from; it is forwarded verbatim.
struct DepositAccounts<'a> {
    depositor: &'a AccountView,
    recipient_vka: &'a AccountView,
    zone_auth: &'a AccountView,
    spp_program: &'a AccountView,
    tree: &'a AccountView,
    settlement: &'a [AccountView],
}

impl<'a> DepositAccounts<'a> {
    fn validate_and_parse(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let depositor = iter.next_account("depositor")?;
        let recipient_vka = iter.next_account("recipient_viewing_key_account")?;
        let zone_auth = iter.next_account("zone_auth")?;
        let spp_program = iter.next_account("spp_program")?;
        let tree = iter.next_account("tree")?;
        let settlement = iter.remaining_unchecked()?;
        Ok(Self {
            depositor,
            recipient_vka,
            zone_auth,
            spp_program,
            tree,
            settlement,
        })
    }
}

/// `deposit` (tag 1): move public funds into a new zone-owned UTXO through the
/// SPP. The depositor signs and funds the transfer; the recipient `owner` is
/// derived on-chain from the recipient viewing key account so the deposited leaf
/// matches the zone spend circuit (`Poseidon(vka.owner, vka.nullifier_pubkey)`).
#[inline(never)]
pub fn process_deposit_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        DepositIxData::deserialize(data).map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    let accs = DepositAccounts::validate_and_parse(accounts)?;

    // Signer checks live in the processor (not nested in helpers).
    if !accs.depositor.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }

    let settlement_len = accs.settlement.len();
    if settlement_len != SOL_SETTLEMENT_ACCOUNTS && settlement_len != SPL_SETTLEMENT_ACCOUNTS {
        return Err(SquadsZoneError::InvalidDepositAccounts.into());
    }

    // Owner + discriminator are validated by the loader. The deposited UTXO's
    // owner hash matches the zone spend circuit's `OwnerHashGadget`, so a later
    // `transact` can spend it.
    let vka = load_viewing_key_account(accs.recipient_vka)?;
    let owner = poseidon2(
        &vka.owner.to_bytes(),
        &vka.nullifier_pubkey,
        SquadsZoneError::ProofHashingFailed,
    )?;

    let zone_auth_bump = verify_pda(accs.zone_auth.address(), &[ZONE_AUTH_PDA_SEED], &crate::ID)?;

    let spp_data = build_spp_zone_deposit_data(SppZoneDepositParams {
        view_tag: ix.view_tag,
        owner,
        blinding: ix.blinding,
        amount: ix.amount,
    })?;

    // Forward to SPP's `zone_deposit` account order: [tree, depositor, zone_auth
    // (== SPP `ZoneConfig`), <settlement>, spp_program]. SPP reads a trailing
    // program account, so the SPP program is forwarded too.
    let mut cpi_accounts: Vec<&AccountView> = Vec::with_capacity(4 + settlement_len);
    cpi_accounts.push(accs.tree);
    cpi_accounts.push(accs.depositor);
    cpi_accounts.push(accs.zone_auth);
    for account in accs.settlement {
        cpi_accounts.push(account);
    }
    cpi_accounts.push(accs.spp_program);

    spp_zone_deposit(accs.spp_program, &cpi_accounts, &spp_data, zone_auth_bump)
}
